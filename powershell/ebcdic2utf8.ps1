if ($args.Count -lt 2) {
    Write-Host "Usage: .\ebcdic2utf8.ps1 <input> <output> [codepage]"
    exit
}

$inputFilePath = $args[0]
$outputFilePath = $args[1]

if (-Not (Test-Path $inputFilePath)) {
    Write-Host "Error: The input file '$inputFilePath' does not exist."
    exit
}

# default to code page IMB037
$codePage = if ($args.Count -eq 3) { $args[2] } else { "IBM037" }

$ebcdicEncoding = [System.Text.Encoding]::GetEncoding($codePage)
$utf8Encoding = [System.Text.Encoding]::UTF8

$ebcdicBytes = [System.IO.File]::ReadAllBytes($inputFilePath)
$ebcdicString = $ebcdicEncoding.GetString($ebcdicBytes)
$utf8Bytes = $utf8Encoding.GetBytes($ebcdicString)

[System.IO.File]::WriteAllBytes($outputFilePath, $utf8Bytes)

Write-Host "Conversion complete. UTF-8 file saved to $outputFilePath"
