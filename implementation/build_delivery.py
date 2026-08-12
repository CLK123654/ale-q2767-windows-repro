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
  with (i/'rollout/stages.csv').open(encoding='utf-8',newline='') as h:r=csv.DictReader(h);stages=list(r);expected_header=['stage_id','stage_name','build_shared_enforce','build_shared_warn','build_shared_audit','version','apply_owner'];
  if not stages or r.fieldnames!=expected_header or len({x['stage_id'] for x in stages})!=len(stages):raise ValueError('stage plan differs')
  with (i/'rollout/namespace-policy.csv').open(encoding='utf-8',newline='') as h:r=csv.DictReader(h);policies={x['namespace']:x for x in r};policy_header=['namespace','enforce','warn','audit']
  if r.fieldnames!=policy_header or set(policies)!={'build-signed','buildkit-system','legacy-vendor'}:raise ValueError('namespace policy differs')
  retained=json.loads((i/'rollout/retained-items.json').read_text(encoding='utf-8'))
  if set(retained)!={'runtime_classes','namespaces','usernames','groups','post_apply_checks'} or retained['usernames'] or retained['groups']:raise ValueError('retained item shape differs')
  if len(retained['runtime_classes'])!=1 or len(retained['namespaces'])!=1:raise ValueError('retained item count differs')
  t.mkdir(parents=True);stage_root=t/'stages';stage_root.mkdir();rendered_root=t/'rendered';rendered_root.mkdir();stage_records=[];workload_records=[]
  baseline_names={x['metadata']['name'] for x in namespaces}
  if baseline_names!={'build-shared','build-signed','buildkit-system','legacy-vendor'}:raise ValueError('namespace set differs')
  for stage in stages:
   sd=stage_root/stage['stage_id'];sd.mkdir();ns_out=[]
   for source in namespaces:
    item=json.loads(json.dumps(source));name=item['metadata']['name'];labels=item['metadata'].setdefault('labels',{})
    if name=='build-shared':enforce,warn,audit=stage['build_shared_enforce'],stage['build_shared_warn'],stage['build_shared_audit']
    else:enforce,warn,audit=(policies[name][x] for x in ('enforce','warn','audit'))
    values=[enforce,stage['version'],warn,stage['version'],audit,stage['version']]
    for label,value in zip(LABELS,values):labels[label]=value
    ns_out.append(item);stage_records.append({'stage_id':stage['stage_id'],'namespace':name,'enforce':enforce,'warn':warn,'audit':audit,'version':stage['version'],'apply_owner':stage['apply_owner']})
   (sd/'namespaces.yaml').write_text(yaml.safe_dump_all(ns_out,allow_unicode=True,sort_keys=False),encoding='utf-8')
   workload_source=before if stage['stage_id']=='observe' else safe
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
  results=t/'results';results.mkdir();write_csv(results/'namespace-labels.csv',['stage_id','namespace','enforce','warn','audit','version','apply_owner'],sorted(stage_records,key=lambda x:(x['stage_id'],x['namespace'])));write_csv(results/'workload-changes.csv',['stage_id','namespace','pod_name','run_as_non_root','seccomp_type','allow_privilege_escalation','privileged','capabilities_drop','volume_types','runtime_class'],sorted(workload_records,key=lambda x:(x['stage_id'],x['namespace'],x['pod_name'])))
  retained_rows=[]
  for category in ('runtime_classes','namespaces'):
   for item in retained[category]:retained_rows.append({'category':category,'value':item['value'],'workload':item['workload'],'owner':item['owner'],'reason':item['reason']})
  write_csv(results/'retained-items.csv',['category','value','workload','owner','reason'],retained_rows)
  summary={'package_scope':'LOCAL_RENDERED_MANIFESTS','stage_count':len(stages),'namespace_record_count':len(stage_records),'workload_record_count':len(workload_records),'retained_item_count':len(retained_rows),'cluster_actions_owner':'平台管理员','cluster_actions':retained['post_apply_checks'],'note':'本地清单只记录准备情况，不代表API Server的真实准入结果'}
  (results/'release-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');(t/'RELEASE-NOTES.md').write_text('# 共享构建区安全收紧说明\n\nrendered目录保存三个维护窗口的本地清单。legacy-buildkit由build-platform负责，legacy-vendor由vendor-transition负责，两者在完成迁移前保持现状。\n\n平台管理员选择阶段目录应用后，再查看Namespace标签、目标Pod替换结果与集群准入日志。本地渲染不代表API Server的真实准入结果。\n',encoding='utf-8');t.replace(o);return 0
 except Exception as e:
  if t.exists():shutil.rmtree(t)
  if o.exists():shutil.rmtree(o)
  print(str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
