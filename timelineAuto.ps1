# timeline automation

# Not very sure this is working properly as the .registry.body seems to have only one date. Don't know where the problem is

# $machines = "FLD-SARIYADH-43"
# $registry = "config.system"

$machines = "FLD-SARIYADH-43", "ENG-USTXHOU-148" #, "IIS-SARIYADH-03", "DC-USTXHOU"
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

    $registryFiles = Get-ChildItem -Path $dir
    $output = -join ($dir, '.registry.body')
    Foreach ($file in $registryFiles) {
        $timelineCommand = "python timeline.py --body $dir\$file >> $output"
        $timelineCommand
        Invoke-Expression $timelineCommand
    }

    $shortRegistry = -join ($short, ' Registry')
    (Get-Content $output).Replace('Registry', $shortRegistry) | Set-Content $output

}
