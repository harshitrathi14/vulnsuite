"""Install repository-pinned scanner releases in a dedicated directory."""
import concurrent.futures
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile
ROOT = Path('/mnt/harshitrathi/vulnsuite/.tools/bin')
ROOT.mkdir(parents=True,exist_ok=True)
ITEMS = {
 'trivy':('https://github.com/aquasecurity/trivy/releases/download/v0.76.0/trivy_0.76.0_Linux-64bit.tar.gz','tar'),
 'gitleaks':('https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz','tar'),
 'osv-scanner':('https://github.com/google/osv-scanner/releases/download/v1.7.4/osv-scanner_linux_amd64','bin'),
 'trufflehog':('https://github.com/trufflesecurity/trufflehog/releases/download/v3.74.0/trufflehog_3.74.0_linux_amd64.tar.gz','tar'),
 'dockle':('https://github.com/goodwithtech/dockle/releases/download/v0.4.14/dockle_0.4.14_Linux-64bit.tar.gz','tar'),
 'kubescape':('https://github.com/kubescape/kubescape/releases/download/v3.0.8/kubescape-ubuntu-latest','bin'),
 'subfinder':('https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip','zip'),
 'httpx':('https://github.com/projectdiscovery/httpx/releases/download/v1.6.5/httpx_1.6.5_linux_amd64.zip','zip'),
 'nuclei':('https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip','zip'),
 'syft':('https://github.com/anchore/syft/releases/download/v1.2.0/syft_1.2.0_linux_amd64.tar.gz','tar'),
 'cosign':('https://github.com/sigstore/cosign/releases/download/v2.2.4/cosign-linux-amd64','bin'),
 'kubectl':('https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl','bin'),
 'helm':('https://get.helm.sh/helm-v3.14.4-linux-amd64.tar.gz','tar'),
}
def install(item):
 name,(url,kind)=item
 try:
  r=subprocess.run(['curl','-fLsS','--retry','2','--max-time','180',url],capture_output=True,check=True)
  data=r.stdout
  if kind=='tar':
   with tarfile.open(fileobj=io.BytesIO(data)) as t:
    member=next(m for m in t.getmembers() if Path(m.name).name==name and m.isfile())
    data=t.extractfile(member).read()
  elif kind=='zip':
   with zipfile.ZipFile(io.BytesIO(data)) as z:
    data=z.read(next(n for n in z.namelist() if Path(n).name==name))
  (ROOT/name).write_bytes(data); (ROOT/name).chmod(0o755)
  return name,'installed'
 except Exception as exc:
  return name,str(exc)[:180]
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 results=dict(pool.map(install,ITEMS.items()))
print(json.dumps(results,indent=2))
Path('/mnt/harshitrathi/vulnsuite/runtime/scanner-install.json').write_text(json.dumps(results,indent=2))
