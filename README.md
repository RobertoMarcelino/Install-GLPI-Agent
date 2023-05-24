This powershell script uninstalls the FusionInventory-Agent and installs the GLPI-Agent and can be used through GPO.

I downloaded the 32-bit and 64-bit versions of the GLPI-Agent installer and copied it to the \\server\netlogon folder.

The Set-RegistryKeys function checks the station name and adds it to the corresponding group (entity).

The initial parameter $IsServer is to check if information is being passed that the installation is being performed on a server that will collect all the data. In this case, the $SetupOptions variable will be added ADDLOCAL=ALL.

The Uninstall-GLPI-Agent function checks if the installation is correct, otherwise it removes and performs a new installation.

This is a job that took a lot of time, countless tests and had the invaluable help of ChatGPT.
