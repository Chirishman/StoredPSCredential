function Read-StoredCredentialList{
    Param()
    Get-Item HKCU:\Software\Microsoft\Windows\PowerShell\Creds -ErrorAction SilentlyContinue | % { $_.GetValueNames() }
}

function Get-StoredCredential {
    [CmdletBinding()]
    Param()
    DynamicParam {
        
        $settings = @(
            ($true | select @{
                    N="Name"
                    E={"CredName"}
                },@{
                    N="SetScript"
                    E={
                        {
                            Read-StoredCredentialList
                        }
                    }
                }
            )
        )

        $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary

        $count = ($PSBoundParameters | measure).Count - 1
        $settings | %{
            $count++
            $attributes = New-Object System.Management.Automation.ParameterAttribute -Property @{ParameterSetName = "__AllParameterSets";Mandatory = $true;Position = $count;ValueFromPipeline = $true;ValueFromPipelineByPropertyName = $true}

            $attributeCollection = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            $ValidateSet = New-Object System.Management.Automation.ValidateSetAttribute($(& $_.SetScript))
            $attributeCollection.Add($ValidateSet)

            $ThisParam = New-Object -Type System.Management.Automation.RuntimeDefinedParameter($_.Name, [string], $attributeCollection)

            $paramDictionary.Add($_.Name, $ThisParam)
        }

        return $paramDictionary 
    }

    begin {
        $settings | %{
            New-Variable -Name $_.Name -Value $PSBoundParameters[$_.Name]
        }
    }
    process{
        if ($_){
            [System.Management.Automation.PSSerializer]::DeSerialize((Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\PowerShell\Creds" -Name $_.CredName))
        } else {
            [System.Management.Automation.PSSerializer]::DeSerialize((Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\PowerShell\Creds" -Name $CredName))
        }
    }
    end {}
}

function Initialize-StoredCredential {
    Param(
    
		[Parameter(Position=0,
			Mandatory=$True,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$true)]
			[string]$CredName,
        [Parameter(Position=1,
			Mandatory=$True)]
			[pscredential]$Credential,
		[Parameter(Position=2,
			Mandatory=$false,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$true)]
			[switch]$Force
    )
    DynamicParam {}

    begin {
        $RegPath = @('HKCU:','Software','Microsoft','Windows','PowerShell','Creds')

        0..($RegPath.Length-1) | %{
            $ThisLevel = (-join(($RegPath[0..$_] -join "\"),"\"))
            if (-not (Test-Path $ThisLevel)){
                Write-Verbose "Creating $ThisLevel"
                New-Item $ThisLevel -ItemType Directory | Out-Null
            }
        }
    }
    process{
        if ($CredName -notin (Read-StoredCredentialList) -or $Force){
            if (-not($Credential)){
                $Credential = (Get-Credential)
            }
            if($Force) {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\PowerShell\Creds\" -Name $CredName -Value ([System.Management.Automation.PSSerializer]::Serialize($Credential)) | Out-Null
            } else {
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\PowerShell\Creds\" -PropertyType String -Name $CredName -Value ([System.Management.Automation.PSSerializer]::Serialize($Credential)) | Out-Null
            }
        } else {
            $Exception = @{
                Message = (-join("A credential with the name ",$CredName," already exists."))
                RecommendedAction = "Choose another name or use the -Force flag to overwrite."
                Category = "WriteError"
                CategoryTargetName = "HKCU:\Software\Microsoft\Windows\PowerShell\Creds\ - $CredName"
                CategoryTargetType = "RegistryKey Property"
                TargetObject = Get-ItemPropertyValue HKCU:\Software\Microsoft\Windows\PowerShell\Creds -Name $CredName
            }
            Write-Error @Exception
        }
    }
    end {}
}

function Remove-StoredCredential {
    [CmdletBinding(
        SupportsShouldProcess=$True
    )]
    Param()
    DynamicParam {
        
        $settings = @(
            ($true | select @{
                    N="Name"
                    E={"CredName"}
                },@{
                    N="SetScript"
                    E={
                        {
                            Read-StoredCredentialList
                        }
                    }
                }
            )
        )

        $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary

        $count = ($PSBoundParameters | measure).Count - 1
        $settings | %{
            $count++
            $attributes = New-Object System.Management.Automation.ParameterAttribute -Property @{ParameterSetName = "__AllParameterSets";Mandatory = $true;Position = $count;ValueFromPipeline = $true;ValueFromPipelineByPropertyName = $true}

            $attributeCollection = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            $ValidateSet = New-Object System.Management.Automation.ValidateSetAttribute($(& $_.SetScript))
            $attributeCollection.Add($ValidateSet)

            $ThisParam = New-Object -Type System.Management.Automation.RuntimeDefinedParameter($_.Name, [string[]], $attributeCollection)

            $paramDictionary.Add($_.Name, $ThisParam)
        }

        return $paramDictionary 
    }

    begin {
        $settings | %{
            New-Variable -Name $_.Name -Value $PSBoundParameters[$_.Name] -WhatIf:$false
        }
    }
    process{
        if ($_) {
            $_.CredName | %{
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\PowerShell\Creds" -Name $_
            }
        } else {
            $CredName | %{
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\PowerShell\Creds" -Name $_
            }
        }
    }
    end {}
}
