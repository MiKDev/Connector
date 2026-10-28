const fs=require('node:fs'),path=require('node:path');
const {execFileSync}=require('node:child_process');
const binary=process.env.CONNECTOR_7ZIP||(process.platform==='win32'?'C:/Program Files/7-Zip/7z.exe':'7z');
const meta=JSON.parse(fs.readFileSync('runtime-cache/downloads-verified.json','utf8'));
execFileSync(binary,['x',path.resolve('runtime-cache',meta.iso),'-o'+path.resolve('runtime-cache/iso'),'boot/vmlinuz-virt','boot/initramfs-virt','boot/modloop-virt','-y'],{windowsHide:true,stdio:'pipe'});
if(process.platform==='win32')execFileSync(binary,['x',path.resolve('runtime-cache',meta.qemu),'-o'+path.resolve('vpn-runtime/qemu'),'-y'],{windowsHide:true,stdio:'pipe'});
console.log('Verified gateway components extracted.');
