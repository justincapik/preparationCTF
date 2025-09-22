pour setup des VMs kali et windows:
1. set **Preferences** > **Default Machine Folder** : "/tmp/VMs"
2. mattre en place le fichier .vagrant.d (là où sont saufgardé les box vagrantes):
```bash
mkdir ~/goinfre/vagrant_home
ln -s ~/sgoinfre/vagrant_home ~/.vagrant.d
```
3. lancer la vm:
```bash
cd path/to/clone/preparationCTF
cd vagrant_files

# pour lancer la machine windows
vagrant up windows-target

# pour lancer la machine kali
vagrant up kali

# pour les deux
vagrant up
```
4. ajouter ce que vous voulez dans le ficher partagé `files`
