function Get-TestA
{
	$test = 23
	Write-Host "Floor 1 - Test: $test"
	Write-Host "Script  - Test: $script:test"
	Get-TestB
	Write-Host "Script  - Test: $script:test"
	Write-Host "Floor 1 - Test: $test"
}

function Get-TestB
{
	$test = 13
	Write-Host "Floor 2 - Test: $test"
	Write-Host "Script  - Test: $script:test"
	Get-TestC
	Write-Host "Script  - Test: $script:test"
	Write-Host "Floor 2 - Test: $test"
}

function Get-TestC
{
	$test = 27
	Write-Host "Floor 3 - Test: $test"
	Write-Host "Script  - Test: $script:test"
	Write-Host "Changing Script-Level Variable to 99"
	$script:test = 99
	Write-Host "Script  - Test: $script:test"
	Write-Host "Floor 3 - Test: $test"
}
$test = 42
Write-Host "Script  - Test: $test"
Get-TestA
Write-Host "Script  - Test: $test"