# Generate PROFIBUS-DP sample capture file
$ErrorActionPreference = "Stop"
$outputPath = "d:\trae3\a82\test_samples\sample_profibus_capture.bin"

# Create directory
New-Item -ItemType Directory -Force -Path (Split-Path $outputPath) | Out-Null

function Build-ProfibusFrame {
    param(
        [byte]$SlaveAddr,
        [byte]$MasterAddr,
        [byte]$FC,
        [byte[]]$PduData
    )
    $totalLen = [byte](6 + $PduData.Length + 2)
    $frame = New-Object System.Collections.Generic.List[byte]
    $frame.Add(0x10)           # SD: Start Delimiter
    $frame.Add($totalLen)      # LE: Length
    $frame.Add($totalLen)      # LEr: Length repeat
    $frame.Add($FC)            # FC: Frame Control
    $frame.Add($SlaveAddr)     # DA: Destination Address
    $frame.Add($MasterAddr)    # SA: Source Address
    $frame.AddRange($PduData)  # PDU

    # Calculate FCS (sum from DA to end of PDU)
    $fcs = [byte]0
    for ($i = 4; $i -lt $frame.Count; $i++) {
        $fcs = ($fcs + $frame[$i]) -band 0xFF
    }
    $frame.Add($fcs)
    $frame.Add(0x16)  # ED: End Delimiter
    return ,$frame.ToArray()
}

function Get-RandomByte {
    param([byte]$Min = 0, [byte]$Max = 255)
    return [byte](Get-Random -Minimum $Min -Maximum ($Max + 1))
}

$capture = New-Object System.Collections.Generic.List[byte]

$slaves = @(
    @{Addr = 3;  Name = "S7-1200_CPU"},
    @{Addr = 5;  Name = "ET200S_IO"},
    @{Addr = 7;  Name = "MM440_VFD"},
    @{Addr = 10; Name = "FESTO_Cylinder"},
    @{Addr = 15; Name = "Unknown_Device"}
)

$frameCount = 100
Write-Host "Generating $frameCount PROFIBUS-DP frames..."

for ($i = 0; $i -lt $frameCount; $i++) {
    $slaveIdx = $i % $slaves.Count
    $slave = $slaves[$slaveIdx]
    $isResponse = ($i % 2) -eq 1
    $masterAddr = [byte]1

    # Frame Control
    if ($isResponse) {
        $fc = 0xF7  # CSR: ACK + low priority
    } else {
        $fc = 0xF4  # SRD: send/request data with low priority
    }

    $pdu = switch ($i % 8) {
        0 {
            # Data Exchange Request (master -> slave output data)
            $p = New-Object byte[] (1 + 4)
            $p[0] = 0x00  # DataExchange SAP
            for ($j = 1; $j -lt $p.Length; $j++) { $p[$j] = Get-RandomByte }
            $p
        }
        1 {
            # Data Exchange Response (slave -> master input data)
            $p = New-Object byte[] (1 + 6)
            $p[0] = 0x00
            # status bits
            $p[1] = Get-RandomByte -Max 0x03
            $p[2] = 0x00
            # int16 motor speed @ offset 2
            $speed = [Int16](Get-Random -Minimum 0 -Maximum 3000)
            $spBytes = [BitConverter]::GetBytes($speed)
            $p[3] = $spBytes[0]
            $p[4] = $spBytes[1]
            # uint16 counter @ offset 4
            $ctr = [UInt16](Get-Random -Minimum 0 -Maximum 9999)
            $ctrBytes = [BitConverter]::GetBytes($ctr)
            $p[5] = $ctrBytes[0]
            $p[6] = $ctrBytes[1]
            $p
        }
        2 {
            # SlaveDiagnostic Request
            [byte[]](0x5E, 0x00, 0x00)
        }
        3 {
            # SlaveDiagnostic Response - normal
            [byte[]](0x5E, 0x00, 0x00, 0x00, 0x00, 0x00)
        }
        4 {
            # SlaveDiagnostic Response - with fault
            # station_not_ok @ bit0 + config fault
            [byte[]](0x5E, 0x05, 0x00, 0x05, 0x00, 0x00)
        }
        5 {
            # SetPrm Request
            [byte[]](0x51, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x20)
        }
        6 {
            # ChkCfg Request
            [byte[]](0x52, 0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x20)
        }
        default {
            # Plain DataExchange
            $p = New-Object byte[] (1 + 4)
            $p[0] = 0x00
            for ($j = 1; $j -lt $p.Length; $j++) { $p[$j] = Get-RandomByte }
            $p
        }
    }

    # Add some random padding bytes occasionally (simulate capture artifacts)
    if ($i -gt 0 -and $i % 12 -eq 0) {
        $padding = New-Object byte[] 3
        for ($j = 0; $j -lt $padding.Length; $j++) { $padding[$j] = Get-RandomByte -Min 0x01 -Max 0x0F }
        $capture.AddRange($padding)
    }

    $frame = Build-ProfibusFrame -SlaveAddr $slave.Addr -MasterAddr $masterAddr -FC $fc -PduData $pdu
    $capture.AddRange($frame)
}

[System.IO.File]::WriteAllBytes($outputPath, $capture.ToArray())
$size = (Get-Item $outputPath).Length
Write-Host "Done! File saved to: $outputPath"
Write-Host "Total size: $size bytes, $frameCount frames"
