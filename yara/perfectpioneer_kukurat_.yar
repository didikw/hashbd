import "hash"
import "pe"

rule MAL_APT_PerfectPioneer_SHA256_20251125
{
    meta:
        description = "PerfectPioneer RAT (RatAAkk-tt, PerfectRAT, newhttp3, rat_http3_ls, rat_http3_cc, Pioneer) - known SHA-256 sample set"
        author = "SOC - CSIRT"
        date = "2025-11-25"
        reference = "PerfectPioneer RAT campaign IOC set"
        malware_family = "PerfectPioneer RAT"
        confidence = "high"
        tlp = "AMBER"
    condition:
        filesize > 0 and filesize < 100MB and
        hash.sha256(0, filesize) matches /^(2281e754f70e11298db1a0a7c1b527cf2b5eec2056d4c73a46ed572ab873dc6e|9721d65ee7695db2b3dc3705f5d8e5efe3a478c3b6d1704d66daf77fe95aeb0d|d725ad8b523c94f99fca9e72a650e835dca47b9ebe7610d6c4eb3525d410c365|f4c9d5d13c1a09533876a02f6fa04831efbf600b05cfb3ed765a0ebde82b0457|19bb3012d846f3672fb98dad0449ae5c267ab30150800b2f1559036564c7d0b8|92fb9545ea49e2fb4635fce1859ff3f609738be75f85d146614243fc8bc80b67|ab06f540ecdd1d45491aa71bfc04c80852371c8f5cd43b9a6ebb53f1e1b69588|bf59f8d7ef79b09a72bbb9c05ca8746466d03226a3779cc1096ba067117ca008|8bf9401990d3255d1022a25884b02ee75ef01bd1a729d29ff52de2e5f0d637a2|5f857ff78bfbef2a55a846fc93744e11e07a9b72ee3fc3bc345c32ce9615ddee|61f7e2f4159c566578e88cb05cdf49e4378f45ebddbd332224e97c11df922120|5b7effbf0465c05e8dc9a8fea69b000a78237735ea0b854e8d9baee5b7af8344|cd8f43da32849584751eec884cf7e3208eb0a71108197a32e9bb248612e757d2|7541222a1316ec54bf9c8660b923e1d0490a925b2ee92060b1567be7cb1bde4b|cffcd6f2589d3ab4f3693805d1752b7c328a00cc543dd02b129763e179c3f311|5805cb5b0a6fb738ef7c1873b8e5de4281c36c7f440f28717fa9f441c5e0ef17|a6a9ccffadd00b0e75e913b0f851b1f834fd20588df8b89759d9ae49a48c8e10|b975f5932c04b381f8fa58a3303194f1aff950d3c6cd12dcc1d323bb3393718b|904409ce8846394e1fe9a5ce37f2265cbf6933611278ae57fdf5fa74759af2bb|d700b573ea8387efad633a70124b7a2a3aece844a267157b1cb55be7b62f3b67|52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07|8cfe629fc08ae06c8ba106113ba30bb16fa2fbbf8bd3dd6831d16b031e0ebe70|619b749e1c6634d38f15c51005a4237e9076aaaf36927b562a990e8bc34fdfcb|fb5b0b1d083d6f6afa90948bd1fd1a498b51dd3f6dc7f90a02a2a17818756563|183abf82951c2052e9a1829c70c173c11756e8df0e86c8071c27df0988caeaa0|0533365accbba405757de7eb486533c11c8e0510a28d414ee8c5e6b8a41ed97b|3cb5376a5e6c0fcbd6844ab76f3dc73a42da7ecee6ecaaef285d4abe33964fa1|f5ebe85418655d75d1a760543858846db1478a060875fd19ddaa5e2febc038d7|b5bea4d8b94fbb39ac992e8e763680af6f39d12d42e264b43431fb61cf7b9a88|7745523939fc6b31b6a73d8ca1f363c62438b6eef56f6fe8c39e71fcd14b65f4|0c49e1b98a236d3391740473101b66dd48c719fa4112dbef3816b56bce58e6e7|24c46bc9269e1c1ee54004e01d5c7c54f759bc1b93a282d3561d2d27f678af86|e5689e1bf916c2f7649e178008e790ea13eb844aefc14516c06b0da8296377a1|63eac14921f138fffe73db417c12afd16d64202ebbee7ad5f08068697d2942d0|790e6699704395a7fad633f4e502312bc43693a44a8e18d43239209eefbd7ff2|f82c06184ab36e91d28f7802c739e637792c241a7ff2fba9ca24178f12423684|2e52b2936e67872d1364d2d0d26a8733ed9582b38f6f0b3a877ffdd6e2c04aa4|9dfefc7118646535d1193e1b036dd0c93fa66cc585a60301fcdceb6f45903aad|600572a912650b258d56aedeef0ab712abbe35a38cdd23faa5a95dacfdc67b7f|86194c3b3cc7a58e439621aff42e116ca94d40f3a6f539f20ce483f1cf5a7191|e8cd6bbcf6073669a7415ce0c9009a0fbb5551bf5e17803be12ef295f0c99889|5b779b81a9bb25591ecac6bd74bb44a4a5b2b8f257093f9efd5910346ab8d772|c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02|bf8afbd1c2074c7cd6ff8b86dbe67a57ca5594817e46b24e226b71c4edde7697)$/
}

rule MAL_KUKURAT_SHA256_20251125
{
    meta:
        description = "KUKURAT HTTP/2-HUP implant, watchdog process and PsExecService module - known SHA-256 sample set"
        author = "SOC - CSIRT"
        date = "2025-11-25"
        reference = "KUKURAT IOC set"
        malware_family = "KUKURAT"
        confidence = "high"
        tlp = "AMBER"
    condition:
        filesize > 0 and filesize < 100MB and
        hash.sha256(0, filesize) matches /^(b8dca1c7e7a74ce82ab4e4cad9b718a458735d2c6c956e4cf3109aac59bfd0e4|9fb0976fcd1f92c4711726a91cff8be9a39944efedc4caf2d80f935327f8f490|7225ef57161cf0908560811be798d22e9354c071d576540a43aa7900784c0688|a214d264c6bb0d2ba89986f73e196ea200307574745a245fc42c32fbef4cc140|662dc73e11b60b2f12c94b6b68da45de7bffece4b1dcc75679ed020629d0705d|b062b4d8c19baf5c1568e28b3e0a5e2318e9501ea61ddfe804d9755c1bdbf887|34cc9bc4a533b91e7cdb30fecc57ba609dc890780fd13ecfbc253047b3b37b78)$/
}

rule WEBSHELL_SHA256_20251125
{
    meta:
        description = "Web shell payloads (ASPXSpy, Godzilla, Bysunue.aspx, Suo5 family) used for initial access - known SHA-256 sample set"
        author = "SOC - CSIRT"
        date = "2025-11-25"
        reference = "Web shell IOC set"
        malware_family = "webshell"
        confidence = "high"
        tlp = "AMBER"
    condition:
        filesize > 0 and filesize < 5MB and
        hash.sha256(0, filesize) matches /^(99f571c07170250a84f0ae9de4179044df91244855d9b39978729933ea3d438f|7ee22a7b028102bb22f0a41d41cd101d5956c1db0cfd157b22bf4128bd472a4f|571067cc8f4224a4b80113b52672c7ac87e25dcdb0282a36a29a1784a24efa27|8d8ccf24b785a33a9388043baecc4be247ad01182b87df3f8e425957ef73087c|0e01c44e5a0615098d8c583930dd88dbd0ce6fe54b365c9f04d8b315a93f540a|1dd423ff0106b15fd100dbc24c3ae9f9860a1fcdb6a871a1e27576f6681a0850|04be76217500275335e82eb4c2c1588478f7a171efd7a0d9bdc6bbe83e315589|3deb43cc864f2322d374541d99af79d87ad08abf81cd967862c554f1c0c5fdb6|224ed1d3f8d7247989f812cb0accc1d1804197916c47d9600e6c4e9bef46a723|9b16333820189e94b2368e87cba0a9642595d5be0f985a6351f1ad834f5cd11d|bdcd0eefc62721814d0bd557285490aa99a4eb0425bf5204e6be16ec7ce93823|3e56d049f23ed45a7034e5c74bad45cae11ce6d15189fa7bda6b8d120439c7cc|834491282da22555f53b769ef8ad91a958f860c583ee5cb67b3f161caf19f854)$/
}

rule HKTL_SharpDPAPI_Unattributed_SHA256_20251125
{
    meta:
        description = "SharpDPAPI credential-theft tooling and unattributed samples co-observed in the same incident - known SHA-256 sample set"
        author = "SOC - CSIRT"
        date = "2025-11-25"
        reference = "Incident IOC set (unmapped files + SharpDPAPI)"
        malware_family = "SharpDPAPI"
        confidence = "medium"
        tlp = "AMBER"
    condition:
        filesize > 0 and filesize < 100MB and
        hash.sha256(0, filesize) matches /^(0cbde9b7f59dafca80f214121a04eda7804b920da28ce1c06939a4783e6b097f|cdc9757294d3063eb10c9a37d1d945d31f6857c652b864803815406b02eeefbf|82a989c728db4e09a2b85a4a55f7663cefa62844632cb16dcda5ca70bf09a8a5|71d897427329ca14dd621e777046dc35f3d9dc870d3b13a56125125391a56afe|6781f84417d0056df95ed38b3e7a6b49312d30119470356f6923238d49de3490|dd02d28c48cf5cabd35a0b32e05e7c99ff0de35541201026ae36c59e54968c78|e59b08eb03ffa10ccf9103d171af757308e6d43519c4e904ef5e0929ef92d8fd)$/
}

rule MAL_APT_PerfectPioneer_KUKURAT_Strings_20251125
{
    meta:
        description = "PerfectPioneer RAT / KUKURAT - embedded build paths, module names, named pipes, staging directory, registry keys and C2 endpoint strings"
        author = "SOC - CSIRT"
        date = "2025-11-25"
        reference = "PerfectPioneer RAT / KUKURAT artifact set"
        malware_family = "PerfectPioneer RAT, KUKURAT"
        confidence = "medium"
        tlp = "AMBER"
    strings:
        $pdb_01 = "D:/proj/http3/newhttp3/agent/" ascii
        $pdb_02 = "D:/proj/RatAAkk-tt/agent/" ascii
        $pdb_03 = "D:/proj/PerfectRat/agent/" ascii
        $pdb_04 = "D:/proj/http3/rat_http3_ls/agent/" ascii
        $pdb_05 = "D:/proj/http3/Pioneer/" ascii
        $pdb_06 = "D:/proj/http3/rat_http3_cc/" ascii
        $pdb_07 = "d:\\proj\\KUKURAT\\modules\\MyPsExec-master\\PsExecService\\" ascii nocase

        $pip_01 = "\\\\.\\pipe\\PSEXEC" ascii nocase
        $pip_02 = "WINDOW_SEC_WATCHDOG" ascii

        $mod_01 = "PsExecService.exe" ascii nocase
        $mod_02 = "SecurityGuard.exe" ascii nocase
        $mod_03 = "BofLoader.dll" ascii nocase
        $mod_04 = "MyPsExec.dll" ascii nocase
        $mod_05 = "SmbBrute.dll" ascii nocase
        $mod_06 = "yuze_dll.dll" ascii nocase
        $mod_07 = "ComExec.dll" ascii nocase

        $stg_01 = "C:\\ProgramData\\Cyvera\\Ransomware\\" ascii nocase

        $reg_01 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $reg_02 = "Software\\Google\\Chrome\\BrowserCrashRecovery" ascii nocase
        $reg_03 = "Software\\Google\\Update\\ClientState" ascii nocase

        $url_01 = "/agent/register" ascii
        $url_02 = "/agent/heartbeat" ascii
        $url_03 = "/agent/tasks" ascii
        $url_04 = "/agent/result" ascii
        $url_05 = "/c8a4e192" ascii

        $dom_01 = "maui-cocktailbar.com" ascii nocase
        $dom_02 = "ads-edge.com" ascii nocase
        $dom_03 = "cloudflacecdn.com" ascii nocase
        $dom_04 = "investigationj6.com" ascii nocase
        $dom_05 = "sacofficegov.com" ascii nocase

        $ip_01 = "27.254.164.212" ascii
        $ip_02 = "27.254.164.209" ascii

    condition:
        // uint16(0) == 0x5A4D and filesize < 20MB and
        pe.is_pe and
        filesize >= 2 and
        filesize < 20MB and
        (
            ( 1 of ($pdb_*) )
            or ( 1 of ($pip_*) and 2 of ($mod_*) )
            or ( 1 of ($pip_*) and 1 of ($stg_*) )
            or ( 1 of ($stg_*) and 2 of ($mod_*) )
            or ( 2 of ($mod_*) and 1 of ($url_*) )
            or ( 2 of ($reg_*) )
            or ( 1 of ($dom_*) and 1 of ($url_*) )
            or ( 1 of ($ip_*) and 1 of ($url_*) )
        )
}
