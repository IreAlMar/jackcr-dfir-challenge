# timeline automation

# $machine = "FLD-SARIYADH-43"
# $registry = "config.system"

$machines = "FLD-SARIYADH-43", "ENG-USTXHOU-148", "IIS-SARIYADH-03", "DC-USTXHOU"
$registry = "config.system", "config.security", "config.sam", "config.default", "config.software", "ntuser.dat", "usrclass.dat"

Foreach ($machine in $machines) {

    $image = -join ($machine, '\memdump.bin')
    $dir = -join ('evidence\REG\', $machine)
    $short = $machine.split('-')[0]
    $short

    if (!(Test-Path -Path $dir )) {
        New-Item -ItemType directory -Path $dir
    }

    Foreach ($key in $registry) {
        $command = ".\vol.exe -f $image dumpfiles -i --regex $key$ -D $dir"
        $command
        Invoke-Expression $command        
    }
}