$Log4JVulnerableHashes = @('2addabe2ceca2145955c02a6182f7fc5',
'5b1d4e4eea828a724c8b0237326829b3',
'ce9e9a27c2a5caa47754999eb9c549b8',
'1538d8c342e3e2a31cd16e01e3865276',
'9cb138881a317a7f49c74c3e462f35f4',
'578ffc5bcccb29f6be2d23176c0425e0',
'5b73a0ad257c57e7441778edee4620a7',
'e32489039dab38637557882cca0653d7',
'db025370dbe801ac623382edb2336ede',
'152ecb3ce094ac5bc9ea39d6122e2814',
'cd70a1888ecdd311c1990e784867ce1e',
'088df113ad249ab72bf19b7f00b863d5',
'de8d01cc15fd0c74fea8bbb668e289f5',
'fbfa5f33ab4b29a6fdd52473ee7b834d',
'8c0cf3eb047154a4f8e16daf5a209319',
'8d331544b2e7b20ad166debca2550d73',
'5e4bca5ed20b94ab19bb65836da93f96',
'110ab3e3e4f3780921e8ee5dde3373ad',
'0079c907230659968f0fc0e41a6abcf9',
'f0c43adaca2afc71c6cc80f851b38818',
'dd0e3e0b404083ec69618aabb50b8ac0',
'5523f144faef2bfca08a3ca8b2becd6a',
'48f7f3cda53030a87e8c387d8d1e4265',
'472c8e1fbaa0e61520e025c255b5d168',
'2b63e0e5063fdaccf669a1e26384f3fd',
'c6d233bc8e9cfe5da690059d27d9f88f',
'547bb3ed2deb856d0e3bbd77c27b9625',
'4a5177a172764bda6f4472b94ba17ccb',
'a27e67868b69b7223576d6e8511659dd',
'a3a6bc23ffc5615efcb637e9fd8be7ec',
'0042e7de635dc1c6c0c5a1ebd2c1c416',
'90c12763ac2a49966dbb9a6d98be361d',
'71d3394226547d81d1bf6373a5b0e53a',
'8da9b75725fb3357cb9872adf7711f9f',
'7943c49b634b404144557181f550a59c',
'df949e7d73479ab717e5770814de0ae9',
'2803991d51c98421be35d2db4ed3c2ac',
'5ff1dab00c278ab8c7d46aadc60b4074',
'b8e0d2779abbf38586b869f8b8e2eb46',
'46e660d79456e6f751c22b94976f6ad5',
'62ad26fbfb783183663ba5bfdbfb5ace',
'3570d00d9ceb3ca645d6927f15c03a62',
'f5e2d2a9543ee3c4339b6f90b6cb01fc',
'5b1d4e4eea828a724c8b0237326829b3',
'ce9e9a27c2a5caa47754999eb9c549b8',
'1538d8c342e3e2a31cd16e01e3865276',
'9cb138881a317a7f49c74c3e462f35f4',
'578ffc5bcccb29f6be2d23176c0425e0',
'5b73a0ad257c57e7441778edee4620a7',
'e32489039dab38637557882cca0653d7',
'db025370dbe801ac623382edb2336ede',
'152ecb3ce094ac5bc9ea39d6122e2814',
'cd70a1888ecdd311c1990e784867ce1e',
'088df113ad249ab72bf19b7f00b863d5',
'de8d01cc15fd0c74fea8bbb668e289f5',
'fbfa5f33ab4b29a6fdd52473ee7b834d',
'8c0cf3eb047154a4f8e16daf5a209319',
'8d331544b2e7b20ad166debca2550d73',
'5e4bca5ed20b94ab19bb65836da93f96',
'110ab3e3e4f3780921e8ee5dde3373ad',
'0079c907230659968f0fc0e41a6abcf9',
'f0c43adaca2afc71c6cc80f851b38818',
'dd0e3e0b404083ec69618aabb50b8ac0',
'5523f144faef2bfca08a3ca8b2becd6a',
'48f7f3cda53030a87e8c387d8d1e4265',
'472c8e1fbaa0e61520e025c255b5d168',
'2b63e0e5063fdaccf669a1e26384f3fd',
'c6d233bc8e9cfe5da690059d27d9f88f',
'547bb3ed2deb856d0e3bbd77c27b9625',
'4a5177a172764bda6f4472b94ba17ccb',
'a27e67868b69b7223576d6e8511659dd',
'a3a6bc23ffc5615efcb637e9fd8be7ec',
'0042e7de635dc1c6c0c5a1ebd2c1c416',
'90c12763ac2a49966dbb9a6d98be361d',
'71d3394226547d81d1bf6373a5b0e53a',
'8da9b75725fb3357cb9872adf7711f9f',
'7943c49b634b404144557181f550a59c',
'df949e7d73479ab717e5770814de0ae9',
'2803991d51c98421be35d2db4ed3c2ac',
'5ff1dab00c278ab8c7d46aadc60b4074',
'b8e0d2779abbf38586b869f8b8e2eb46',
'46e660d79456e6f751c22b94976f6ad5',
'62ad26fbfb783183663ba5bfdbfb5ace',
'3570d00d9ceb3ca645d6927f15c03a62',
'f5e2d2a9543ee3c4339b6f90b6cb01fc')


$i = 0
$AllFixedDriveLetters = Get-Volume | ? {$_.DriveType -eq "Fixed" -and $_.DriveLetter -ne $null} | Select -ExpandProperty DriveLetter

$AllJarFilesOnAllDrives = @()

Foreach ($DriveLetter in $AllFixedDriveLetters) {
    $AllJarFilesOnAllDrives += Get-ChildItem -Path "$DriveLetter\*.jar" -Recurse -force -ErrorAction SilentlyContinue
}

$AllLog4jNamedJarFiles = @()

$AllLog4jNamedJarFiles = $AllJarFilesOnAllDrives | Where-Object {$_.name -like "log4j*.jar"}

$AllLog4JHashMatches = @()

$AllJarFilesOnAllDrives | Where-Object {$((Get-FileHash -Path "$($_.Fullname)" -Algorithm MD5).Hash) -iin $Log4JVulnerableHashes}

$AllJndiLookupClassMatches = @()

$AllJndiLookupClassMatches = $AllJarFilesOnAllDrives | Where-Object { $( Get-Content -Path "$($_.FullName)" | Select-String "JndiLookup.class" ).Count -gt 0 }

$i = $AllLog4jNamedJarFiles.Count + $AllLog4JHashMatches.Count + $AllJndiLookupClassMatches.count 

If ($i -ge 1) { 
    Write-Host "Vulnerable"
}
Else { 
    Write-Host "Compliant"
}
