// Linux packaging reuses the desktop build and ships the verified guest images.
// QEMU and Python are native system dependencies rather than Windows binaries.
const {build}=require('../package.json');
module.exports={
 ...build,
 extraMetadata:{homepage:'https://github.com/MiKDev/Connector',desktopName:'connector-desktop.desktop'},
 extraResources:[{from:'vpn-runtime',to:'vpn-runtime',filter:['images/**/*','manifest.json','packages.json']}],
 linux:{...build.linux,maintainer:'Connector contributors',syncDesktopName:true},
 deb:{
  compression:'gz',
  depends:['libgtk-3-0 | libgtk-3-0t64','libnotify4','libnss3','libxss1','libxtst6','xdg-utils','libatspi2.0-0 | libatspi2.0-0t64','libuuid1','libsecret-1-0','libasound2 | libasound2t64','libgbm1','libatk-bridge2.0-0 | libatk-bridge2.0-0t64','python3','qemu-system-x86','openssh-client'],
  recommends:['gnome-keyring | kwalletmanager']
 }
};
