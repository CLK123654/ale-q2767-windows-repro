from __future__ import annotations
import argparse,csv,json,shutil,subprocess,sys
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
EXPECTED={'README.md','current/namespaces.yaml','current/workloads.yaml','rollout/stages.csv','rollout/namespace-policy.csv','rollout/retained-items.json'}
LABELS=['pod-security.kubernetes.io/enforce','pod-security.kubernetes.io/enforce-version','pod-security.kubernetes.io/warn','pod-security.kubernetes.io/warn-version','pod-security.kubernetes.io/audit','pod-security.kubernetes.io/audit-version']
def docs(p):return [x for x in yaml.safe_load_all(p.read_text(encoding='utf-8')) if x]
def write_csv(p,fields,rows):
 with p.open('w',encoding='utf-8',newline='') as h:w=csv.DictWriter(h,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows(rows)
def key(x):return x.get('kind',''),x.get('metadata',{}).get('namespace',''),x.get('metadata',{}).get('name','')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True);ap.add_argument('--output',required=True);ap.add_argument('--kubectl',required=True);a=ap.parse_args();i=Path(a.input).resolve();o=Path(a.output).resolve();t=o.parent/f'.{o.name}-building'
 if o.exists():shutil.rmtree(o)
 if t.exists():shutil.rmtree(t)
 try:
  actual={p.relative_to(i).as_posix() for p in i.rglob('*') if p.is_file()}
  if actual!=EXPECTED:raise ValueError('input file set differs')
  namespaces=docs(i/'current/namespaces.yaml');before=docs(i/'current/workloads.yaml');safe=docs(ROOT/'implementation/templates/workloads-safe.yaml')
  if {key(x) for x in before}!={key(x) for x in safe}:raise ValueError('workload identity differs')
  with (i/'rollout/stages.csv').open(encoding='utf-8',newline='') as h:r=csv.DictReader(h);stages=list(r);expected_header=['stage_id','stage_name','window_start_utc','window_end_utc','impact_scope','build_shared_enforce','build_shared_warn','build_shared_audit','version','apply_owner','rollout_wait_minutes','observe_minutes','rollback_stage','rollback_owner'];
  if not stages or r.fieldnames!=expected_header or len({x['stage_id'] for x in stages})!=len(stages):raise ValueError('stage plan differs')
  stage_ids={x['stage_id'] for x in stages}
  if stage_ids!={'current','baseline','restricted'} or any(not x['rollout_wait_minutes'].isdigit() or not x['observe_minutes'].isdigit() or x['rollback_stage'] not in stage_ids or not x['rollback_owner'] for x in stages):raise ValueError('stage window differs')
  for stage in stages:
   if stage['stage_id']=='current':
    if stage['window_start_utc'] or stage['window_end_utc'] or int(stage['rollout_wait_minutes']) or int(stage['observe_minutes']):raise ValueError('current stage must not be a maintenance window')
   elif not stage['window_start_utc'] or not stage['window_end_utc'] or not stage['impact_scope'] or int(stage['rollout_wait_minutes'])<=0 or int(stage['observe_minutes'])<=0:raise ValueError('release window is incomplete')
  with (i/'rollout/namespace-policy.csv').open(encoding='utf-8',newline='') as h:r=csv.DictReader(h);policies={x['namespace']:x for x in r};policy_header=['namespace','enforce','warn','audit']
  if r.fieldnames!=policy_header:raise ValueError('namespace policy differs')
  retained=json.loads((i/'rollout/retained-items.json').read_text(encoding='utf-8'))
  if set(retained)!={'runtime_classes','namespaces','observation_signals','rollback_triggers'}:raise ValueError('retained item shape differs')
  if not retained['runtime_classes'] or not retained['namespaces'] or not retained['observation_signals'] or not retained['rollback_triggers']:raise ValueError('retained item content differs')
  t.mkdir(parents=True);stage_root=t/'stages';stage_root.mkdir();rendered_root=t/'rendered';rendered_root.mkdir();stage_records=[];workload_records=[];plan_records=[]
  baseline_names={x['metadata']['name'] for x in namespaces}
  if 'build-shared' not in baseline_names or set(policies)!=baseline_names-{'build-shared'}:raise ValueError('namespace set differs')
  for stage in stages:
   plan_records.append({k:stage[k] for k in expected_header})
   sd=stage_root/stage['stage_id'];sd.mkdir();ns_out=[]
   for source in namespaces:
    item=json.loads(json.dumps(source));name=item['metadata']['name'];labels=item['metadata'].setdefault('labels',{})
    if name=='build-shared':enforce,warn,audit=stage['build_shared_enforce'],stage['build_shared_warn'],stage['build_shared_audit']
    else:enforce,warn,audit=(policies[name][x] for x in ('enforce','warn','audit'))
    values=[enforce,stage['version'],warn,stage['version'],audit,stage['version']]
    for label,value in zip(LABELS,values):labels[label]=value
    ns_out.append(item);stage_records.append({'stage_id':stage['stage_id'],'namespace':name,'enforce':enforce,'warn':warn,'audit':audit,'version':stage['version'],'apply_owner':stage['apply_owner'],'observe_minutes':stage['observe_minutes'],'rollback_stage':stage['rollback_stage'],'rollback_owner':stage['rollback_owner']})
   (sd/'namespaces.yaml').write_text(yaml.safe_dump_all(ns_out,allow_unicode=True,sort_keys=False),encoding='utf-8')
   workload_source=before if stage['stage_id']=='current' else safe
   (sd/'workloads.yaml').write_text(yaml.safe_dump_all(workload_source,allow_unicode=True,sort_keys=False),encoding='utf-8')
   (sd/'kustomization.yaml').write_text('apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - namespaces.yaml\n  - workloads.yaml\n',encoding='utf-8')
   c=subprocess.run([a.kubectl,'kustomize',str(sd)],text=True,capture_output=True,timeout=120)
   if c.returncode:raise ValueError(c.stdout+c.stderr)
   (rendered_root/f"{stage['stage_id']}.yaml").write_text(c.stdout.replace('\r\n','\n'),encoding='utf-8');rendered=docs(rendered_root/f"{stage['stage_id']}.yaml")
   keys=[key(x) for x in rendered]
   if len(keys)!=len(set(keys)) or {x for x in keys if x[0]=='Pod'}!={key(x) for x in workload_source}:raise ValueError('rendered identity differs')
   for pod in [x for x in rendered if x.get('kind')=='Pod']:
    spec=pod.get('spec',{});container=spec.get('containers',[{}])[0];security=container.get('securityContext',{});volume_types=[]
    for volume in spec.get('volumes',[]):volume_types.extend([k for k in volume if k!='name'])
    workload_records.append({'stage_id':stage['stage_id'],'namespace':pod['metadata']['namespace'],'pod_name':pod['metadata']['name'],'run_as_non_root':str(spec.get('securityContext',{}).get('runAsNonRoot','')).lower(),'seccomp_type':spec.get('securityContext',{}).get('seccompProfile',{}).get('type',''),'allow_privilege_escalation':str(security.get('allowPrivilegeEscalation','')).lower(),'privileged':str(security.get('privileged','')).lower(),'capabilities_drop':'|'.join(security.get('capabilities',{}).get('drop',[])),'volume_types':'|'.join(sorted(volume_types)),'runtime_class':spec.get('runtimeClassName','')})
  results=t/'results';results.mkdir();write_csv(results/'stage-plan.csv',expected_header,plan_records);write_csv(results/'namespace-labels.csv',['stage_id','namespace','enforce','warn','audit','version','apply_owner','observe_minutes','rollback_stage','rollback_owner'],sorted(stage_records,key=lambda x:(x['stage_id'],x['namespace'])));write_csv(results/'workload-changes.csv',['stage_id','namespace','pod_name','run_as_non_root','seccomp_type','allow_privilege_escalation','privileged','capabilities_drop','volume_types','runtime_class'],sorted(workload_records,key=lambda x:(x['stage_id'],x['namespace'],x['pod_name'])))
  retained_rows=[]
  for category in ('runtime_classes','namespaces'):
   for item in retained[category]:retained_rows.append({'category':category,'value':item['value'],'workload':item['workload'],'owner':item['owner'],'reason':item['reason']})
  write_csv(results/'retained-items.csv',['category','value','workload','owner','reason'],retained_rows)
  notes=['# 共享构建区发布说明','', 'current阶段保存变更前清单。legacy-buildkit由build-platform负责，legacy-vendor由vendor-transition负责，两者在完成迁移前保持现状。','', '维护窗口一次只推进一个阶段。']
  for s in stages:
   if s['stage_id']!='current':notes.append(f"{s['stage_name']}安排在{s['window_start_utc']}至{s['window_end_utc']}，影响范围是{s['impact_scope']}。应用后等待{s['rollout_wait_minutes']}分钟，再观察{s['observe_minutes']}分钟；命中回退条件时由{s['rollback_owner']}恢复到{s['rollback_stage']}阶段。")
  notes+=['']
  notes.extend(f"观察信号：{item}" for item in retained['observation_signals'])
  notes.extend(f"回退条件：{item}" for item in retained['rollback_triggers'])
  notes.append('命中任一回退条件时停止本次发布。')
  (t/'RELEASE-NOTES.md').write_text('\n'.join(notes)+'\n',encoding='utf-8');t.replace(o);return 0
 except Exception as e:
  if t.exists():shutil.rmtree(t)
  if o.exists():shutil.rmtree(o)
  print(str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
