
//   <!--   remove this script THIS IS DUMMY DATA by AK-47 -->

    function performScan(scanType) {
        const url = document.getElementById('url').value;
        if (!url) {
            alert('Please enter a valid URL.');
            return;
        }

        const scanResultsDiv = document.getElementById('scan-results');
        scanResultsDiv.innerHTML = 'Scanning...';

        //dummy scan for mid-sem
        setTimeout(() => {
            scanResultsDiv.innerHTML = `Results for ${scanType} on ${url}:<br>- Vulnerability found!<br>- No vulnerabilities found.`;
        }, 2000);
    }

    function scanSecurityHeaders() {
        const url = document.getElementById('url').value;
        if (!url) {
            alert('Please enter a valid URL.');
            return;
        }

        const headerResultsDiv = document.getElementById('header-scan-results');
        headerResultsDiv.innerHTML = 'Scanning for security headers...';

        // Dummy show for mid minor project 
        setTimeout(() => {
            headerResultsDiv.innerHTML = `Security headers for ${url}:<br>- X-Content-Type-Options: nosniff<br>- X-XSS-Protection: 1; mode=block<br>- Content-Security-Policy: default-src 'self';`;
        }, 2000);
    }
