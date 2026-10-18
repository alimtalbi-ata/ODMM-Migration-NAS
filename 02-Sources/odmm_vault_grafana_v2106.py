"""ODMM V210.6 — minimal Grafana dashboard for authenticated Vault HA telemetry.
Author: Abdelhalim Talbi. Import via Grafana dashboards; configure Prometheus auth separately.
"""
import json

def dashboard():
    targets = [
        ('Available Vault endpoints', 'odmm_vault_ha_available_endpoints'),
        ('Vault HA telemetry valid', 'odmm_vault_ha_telemetry_valid'),
        ('Vault HA request rate', 'rate(odmm_vault_ha_requests_total[5m])'),
        ('Vault HA failure rate', 'rate(odmm_vault_ha_failures_total[5m])'),
        ('Vault HA circuit rejections', 'rate(odmm_vault_ha_circuit_rejections_total[5m])'),
    ]
    return {'title':'ODMM — Vault HA Operations', 'uid':'odmm-vault-ha-v2106',
            'schemaVersion':39,'version':1,'refresh':'30s','timezone':'browser',
            'tags':['odmm','vault','ha','read-only'],
            'panels':[{'id':i,'title':title,'type':'timeseries','datasource':{'type':'prometheus','uid':'${DS_PROMETHEUS}'},
                       'targets':[{'expr':expr,'refId':'A'}],
                       'gridPos':{'h':8,'w':12,'x':(i-1)%2*12,'y':(i-1)//2*8}}
                      for i,(title,expr) in enumerate(targets,1)],
            '__inputs':[{'name':'DS_PROMETHEUS','label':'Prometheus','type':'datasource','pluginId':'prometheus','pluginName':'Prometheus'}]}

def export_dashboard(path):
    from pathlib import Path
    Path(path).write_text(json.dumps(dashboard(),indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
