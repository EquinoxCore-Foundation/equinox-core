$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:8088/")
try {
    $listener.Start()
    $root = "E:\equinox-core 0.2\equinox-core\Equinox-Super-Wallet\apps\desktop\src"
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $rel = $ctx.Request.Url.LocalPath.TrimStart('/')
        if ([string]::IsNullOrEmpty($rel)) { $rel = "index.html" }
        $file = Join-Path $root $rel
        if (Test-Path $file -PathType Leaf) {
            $bytes = [System.IO.File]::ReadAllBytes($file)
            if ($file.EndsWith(".html")) { $ctx.Response.ContentType = "text/html; charset=utf-8" }
            elseif ($file.EndsWith(".js")) { $ctx.Response.ContentType = "application/javascript; charset=utf-8" }
            elseif ($file.EndsWith(".css")) { $ctx.Response.ContentType = "text/css; charset=utf-8" }
            $ctx.Response.ContentLength64 = $bytes.Length
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        } else {
            $ctx.Response.StatusCode = 404
        }
        $ctx.Response.Close()
    }
} catch {}
