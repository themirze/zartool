const cpeDescriptions = {
  "cpe:/a:openbsd:openssh": "OpenSSH - Güvenli Uzaktan Bağlantı",
  "cpe:/a:php:php": "PHP - Web Programlama Dili",
  "cpe:/a:oracle:mysql": "MySQL - Veri Tabanı Yönetim Sistemi",
  "cpe:/a:webmin:webmin": "Webmin - Sunucu Yönetim Aracı",
  "cpe:/a:getbootstrap:bootstrap": "Bootstrap - CSS Framework",
  "cpe:/a:apache:http_server": "Apache - Web Sunucusu",
  "cpe:/a:jivochat:jivochat": "JivoChat - Canlı Destek Uygulaması",
  "cpe:/a:jquery:jquery": "jQuery - JavaScript Kütüphanesi",
  "cpe:/a:postfix:postfix": "Postfix - Mail Sunucusu",
};

function fetchIPData() {
  let ip = document.getElementById("ipInput").value.trim();
  let output = document.getElementById("output");
  output.innerHTML = "Yükleniyor...";

  if (!ip) {
    output.innerHTML = "Lütfen geçerli bir IP adresi girin.";
    return;
  }

  let url = `https://internetdb.shodan.io/${ip}`;

  fetch(url)
    .then((response) => response.json())
    .then((data) => {
      output.innerHTML = formatData(data);
      checkPorts(ip, data.ports);
    })
    .catch((error) => {
      output.innerHTML = "Hata oluştu: " + error;
    });
}

function formatData(data) {
  let html = "";

  if (data.cpes && data.cpes.length > 0) {
    html += `<div class='section'><strong>CPE'ler:</strong><ul>`;
    data.cpes.forEach((cpe) => {
      let desc = "Bilinmiyor";
      for (let key in cpeDescriptions) {
        if (cpe.startsWith(key)) {
          desc = cpeDescriptions[key];
          break;
        }
      }
      html += `<li>${cpe} - ${desc}</li>`;
    });
    html += `</ul></div>`;
  }

  if (data.hostnames && data.hostnames.length > 0) {
    html += `<div class='section'><strong>Hostnames:</strong><ul>`;
    data.hostnames.forEach((hostname) => {
      html += `<li><a href="http://${hostname}" target="_blank">${hostname}</a></li>`;
    });
    html += `</ul></div>`;
  }

  if (data.ip) {
    html += `<div class='section'><strong>IP Adresi:</strong> ${data.ip}</div>`;
  }

  if (data.ports && data.ports.length > 0) {
    html += `<div class='section'><strong>Portlar:</strong><div id="ports"></div></div>`;
  }

  if (data.vulns && data.vulns.length > 0) {
    html += `<div class='section'><strong>Güvenlik Açıkları (CVE):</strong><ul class="reference-list">`;
    data.vulns.forEach((cve) => {
      html += `<li><a href="#" onclick="fetchCVEDetails('${cve}'); return false;" class="cve-link">${cve}</a></li>`;
    });
    html += `</ul></div>`;
  }

  return html;
}

function checkPorts(ip, ports) {
  let portsDiv = document.getElementById("ports");
  portsDiv.innerHTML = `
    <div class="loading-ports">
      <p>Portlar kontrol ediliyor...</p>
    </div>
  `;

  let checkPort = (ip, port) => {
    return new Promise((resolve) => {
      const timeout = 5000; // 5 saniye timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      fetch(`http://${ip}:${port}`, {
        method: "HEAD",
        mode: "no-cors",
        signal: controller.signal,
      })
        .then(() => {
          clearTimeout(timeoutId);
          resolve({ port, status: "open", service: getCommonPortService(port) });
        })
        .catch(() => {
          clearTimeout(timeoutId);
          resolve({ port, status: "closed", service: getCommonPortService(port) });
        });
    });
  };

  Promise.all(ports.map((port) => checkPort(ip, port))).then((results) => {
    // Portları sıralayalım (açık olanlar üstte)
    results.sort((a, b) => {
      if (a.status === b.status) {
        return a.port - b.port;
      }
      return a.status === "open" ? -1 : 1;
    });

    portsDiv.innerHTML = "<ul>";
    results.forEach((result) => {
      const statusEmoji = result.status === "open" ? "🟢" : "🔴";
      const serviceInfo = result.service ? ` - ${result.service}` : "";

      portsDiv.innerHTML += `
          <li class="port ${result.status}">
            <span class="port-number">Port ${result.port}${serviceInfo}</span>
            <span class="port-status" title="${result.status === "open" ? "Açık" : "Kapalı"}">${statusEmoji}</span>
                </li>`;
    });
    portsDiv.innerHTML += "</ul>";
  });
}

function getCommonPortService(port) {
  const commonPorts = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Proxy",
  };
  return commonPorts[port] || "";
}

async function fetchCVEDetails(cve) {
  const popup = document.getElementById("cvePopup");
  const detailsDiv = document.getElementById("cveDetails");
  const titleElement = document.getElementById("cveTitle");

  popup.style.display = "block";
  titleElement.textContent = cve;
  detailsDiv.innerHTML = '<div class="loading">Yükleniyor...</div>';

  try {
    // CORS proxy kullanarak isteği yap
    const proxyUrl = "https://api.allorigins.win/get?url=";
    const targetUrl = encodeURIComponent(`https://cvedb.shodan.io/cve/${cve}`);

    const response = await fetch(proxyUrl + targetUrl);
    const proxyData = await response.json();

    // API yanıtını JSON olarak parse et
    const data = JSON.parse(proxyData.contents);

    // CVSS skoruna göre renk sınıfı belirleme
    let cvssClass = "low";
    if (data.cvss >= 9.0) cvssClass = "critical";
    else if (data.cvss >= 7.0) cvssClass = "high";
    else if (data.cvss >= 4.0) cvssClass = "medium";

    // Tekrarlanan referansları temizle
    const uniqueReferences = [...new Set(data.references || [])];

    let html = `
      <div class="cve-detail">
        <div class="cvss cvss-${cvssClass}">
          <strong>CVSS Skoru:</strong> ${data.cvss || "Belirtilmemiş"}
        </div>

        <div class="summary">
          <h4>Açıklama</h4>
          <p>${data.summary || "Açıklama bulunamadı."}</p>
        </div>
        
        ${
          uniqueReferences.length > 0
            ? `<div class="references">
              <h4>Referanslar</h4>
              <ul class="reference-list">
                ${uniqueReferences
                  .map(
                    (ref) => `
                  <li><a href="${ref}" target="_blank" rel="noopener noreferrer">${ref}</a></li>
                `
                  )
                  .join("")}
              </ul>
            </div>`
            : "<p>Referans bulunamadı.</p>"
        }
      </div>
    `;

    detailsDiv.innerHTML = html;
  } catch (error) {
    detailsDiv.innerHTML = `
      <div class="error">
        <p>CVE detayları yüklenirken bir hata oluştu.</p>
        <p>Lütfen tekrar deneyin veya internet bağlantınızı kontrol edin.</p>
      </div>
    `;
    console.error("CVE Detay Hatası:", error);
  }
}

function closePopup() {
  const popup = document.getElementById("cvePopup");
  popup.style.display = "none";
}

// Popup dışına tıklandığında kapatma
document.addEventListener("DOMContentLoaded", () => {
  const popup = document.getElementById("cvePopup");
  popup.addEventListener("click", (e) => {
    if (e.target === popup) {
      closePopup();
    }
  });

  // ESC tuşu ile kapatma
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && popup.style.display === "block") {
      closePopup();
    }
  });

  // Tab işlemleri
  const tabButtons = document.querySelectorAll(".tab-button");
  const tabContents = document.querySelectorAll(".tab-content");

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const tabId = button.dataset.tab;

      // Aktif tab'ı değiştir
      tabButtons.forEach((btn) => btn.classList.remove("active"));
      tabContents.forEach((content) => content.classList.remove("active"));

      button.classList.add("active");
      document.getElementById(tabId).classList.add("active");
    });
  });

  // Dosya yükleme işlemleri
  const fileInput = document.getElementById("fileInput");
  const fileLabel = document.querySelector(".file-label");
  const selectedFile = document.querySelector(".selected-file");
  const analyzeBtn = document.getElementById("bulkAnalyzeBtn");

  fileInput.addEventListener("change", handleFileSelect);

  // Drag & Drop işlemleri
  fileLabel.addEventListener("dragover", (e) => {
    e.preventDefault();
    fileLabel.classList.add("drag-over");
  });

  fileLabel.addEventListener("dragleave", () => {
    fileLabel.classList.remove("drag-over");
  });

  fileLabel.addEventListener("drop", (e) => {
    e.preventDefault();
    fileLabel.classList.remove("drag-over");

    const file = e.dataTransfer.files[0];
    if (file && file.type === "text/plain") {
      fileInput.files = e.dataTransfer.files;
      handleFileSelect();
    }
  });
});

function handleFileSelect() {
  const fileInput = document.getElementById("fileInput");
  const selectedFile = document.querySelector(".selected-file");
  const analyzeBtn = document.getElementById("bulkAnalyzeBtn");

  if (fileInput.files.length > 0) {
    const file = fileInput.files[0];
    selectedFile.textContent = `Seçilen Dosya: ${file.name}`;
    analyzeBtn.disabled = false;
  }
}

async function analyzeBulkIPs() {
  const fileInput = document.getElementById("fileInput");
  const bulkOutput = document.getElementById("bulkOutput");
  const file = fileInput.files[0];

  if (!file) return;

  // Loading göster
  bulkOutput.innerHTML = `
    <div class="loading-container">
      <div class="loading-spinner"></div>
      <p>IP'ler analiz ediliyor...</p>
      <div class="progress-bar">
        <div class="progress"></div>
      </div>
    </div>
  `;

  try {
    const text = await file.text();
    const ips = text
      .split("\n")
      .map((ip) => ip.trim())
      .filter((ip) => ip && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip));

    const totalIPs = ips.length;
    const results = [];
    const progressBar = document.querySelector(".progress");

    // Her IP için analiz yap
    for (let i = 0; i < ips.length; i++) {
      const ip = ips[i];
      try {
        const response = await fetch(`https://internetdb.shodan.io/${ip}`);
        const data = await response.json();

        // Port kontrolü yap
        const openPorts = [];
        if (data.ports && data.ports.length > 0) {
          for (const port of data.ports) {
            try {
              const portResponse = await fetch(`http://${ip}:${port}`, {
                method: "HEAD",
                mode: "no-cors",
                timeout: 2000,
              });
              if (portResponse.status !== 404) {
                openPorts.push(port);
              }
            } catch (error) {
              // Port kapalı veya erişilemiyor
              continue;
            }
          }
        }

        results.push({
          ip: ip,
          ports: openPorts.length,
          openPorts: openPorts,
          cves: data.vulns?.length || 0,
          data: {
            ...data,
            ports: openPorts, // Sadece açık portları data'ya ekle
          },
        });

        // İlerleme çubuğunu güncelle
        const progress = ((i + 1) / totalIPs) * 100;
        progressBar.style.width = `${progress}%`;
      } catch (error) {
        console.error(`Error analyzing IP ${ip}:`, error);
      }
    }

    // Sonuçları sırala (açık port ve CVE sayısına göre)
    results.sort((a, b) => {
      const aScore = a.ports + a.cves;
      const bScore = b.ports + b.cves;
      return bScore - aScore;
    });

    // Sonuçları göster
    displayBulkResults(results, totalIPs);
  } catch (error) {
    bulkOutput.innerHTML = `
      <div class="error">
        <p>Dosya okuma hatası:</p>
        <p>${error.message}</p>
      </div>
    `;
  }
}

function displayBulkResults(results, totalIPs) {
  const bulkOutput = document.getElementById("bulkOutput");

  // Sadece açık portları say
  const totalPorts = results.reduce((sum, item) => sum + item.ports, 0);
  const totalCVEs = results.reduce((sum, item) => sum + item.cves, 0);

  let html = `
    <div class="bulk-stats">
      <h3>Analiz Özeti</h3>
      <p>Toplam IP: ${totalIPs} | Toplam Açık Port: ${totalPorts} | Toplam CVE: ${totalCVEs}</p>
    </div>
    <div class="bulk-results">
  `;

  results.forEach((result) => {
    const portText = result.ports > 0 ? `${result.ports} Açık Port (${result.openPorts.join(", ")})` : "Açık Port Yok";

    html += `
      <div class="ip-result" onclick="showIPDetails('${result.ip}', ${JSON.stringify(result.data).replace(
      /"/g,
      "&quot;"
    )})">
        <div class="ip-info">
          <span class="ip-address">${result.ip}</span>
          <div class="ip-stats">
            <span class="stat-item ports">
              <span class="stat-icon">🔌</span>
              ${portText}
            </span>
            <span class="stat-item cves">
              <span class="stat-icon">🛡️</span>
              ${result.cves} CVE
            </span>
          </div>
        </div>
        <span class="view-details">Detayları Gör →</span>
      </div>
    `;
  });

  html += "</div>";
  bulkOutput.innerHTML = html;
}

function showIPDetails(ip, data) {
  const popup = document.getElementById("ipDetailPopup");
  const detailsDiv = document.getElementById("ipDetails");
  const titleElement = document.getElementById("ipDetailTitle");

  popup.style.display = "block";
  titleElement.textContent = `IP: ${ip}`;
  detailsDiv.innerHTML = formatData(data);

  if (data.ports && data.ports.length > 0) {
    checkPorts(ip, data.ports);
  }
}

function closeIpDetailPopup() {
  const popup = document.getElementById("ipDetailPopup");
  popup.style.display = "none";
}

function openInfoPopup() {
  const popup = document.getElementById("infoPopup");
  popup.style.display = "block";
}

function closeInfoPopup() {
  const popup = document.getElementById("infoPopup");
  popup.style.display = "none";
}

function generateShodanUrl() {
  const input = document.getElementById("shodanUrl").value.trim();
  if (!input) return;

  // URL'i temizle
  let domain = input
    .replace(/^https?:\/\//i, "") // http:// veya https:// kaldır
    .replace(/^www\./i, "") // www. kaldır
    .split("/")[0]; // path'i kaldır

  const shodanUrl = `https://www.shodan.io/search/facet?query=hostname%3A${encodeURIComponent(domain)}&facet=ip`;
  window.open(shodanUrl, "_blank");
}

function addBookmarklet() {
  const bookmarkletCode = `javascript:(function(){function copyToClipboard(text){const textarea=document.createElement("textarea");textarea.value=text;document.body.appendChild(textarea);textarea.select();document.execCommand("copy");document.body.removeChild(textarea)}function downloadFile(filename,content){const blob=new Blob([content],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=filename;document.body.appendChild(a);a.click();document.body.removeChild(a)}const elements=document.querySelectorAll(".four.columns.name strong");let ips=[];elements.forEach(el=>{ips.push(el.textContent.trim())});if(ips.length>0){const ipText=ips.join("\\n");copyToClipboard(ipText);const totalElement=document.querySelector(".grid-heading span");let totalCount=totalElement?totalElement.textContent.trim():ips.length;downloadFile(\`\${totalCount}.txt\`,ipText);alert(\`Toplam \${ips.length} IP adresi kopyalandı ve \${totalCount}.txt olarak kaydedildi.\`)}else{alert("Hiç IP adresi bulunamadı!")}})();`;

  const bookmarkletButton = document.querySelector(".bookmarklet-button");
  bookmarkletButton.href = bookmarkletCode;

  // Kullanıcıya nasıl ekleyeceğini göster
  alert(
    "Bookmarklet'i eklemek için:\n\n1. Tarayıcınızın yer işaretleri çubuğunu gösterin (Ctrl/Cmd + Shift + B)\n2. 'IP Topla' butonunu yer işaretleri çubuğuna sürükleyin\n\nveya\n\n3. 'IP Topla' butonuna sağ tıklayıp 'Yer İşareti Olarak Kaydet'i seçin"
  );
}

// ESC tuşu ile tüm popupları kapatma
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document.getElementById("cvePopup").style.display = "none";
    document.getElementById("ipDetailPopup").style.display = "none";
    document.getElementById("infoPopup").style.display = "none";
  }
});
