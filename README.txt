This is a VERY simple DNS server that gets records from a remote mysql server and returns them so that we can do dynamic resolving.

Installation should be done via the ansible scripts, just add your server to the inventory under either [production] or [staging] and add the private key.
Then run: ansible-playbook -i inventories/<inventory_file> deploy.yml
