//search variable
let httpscertificate;
let sslcertificate;
let domainInput_div = document.getElementById('search_content');

const loading_div = document.getElementById("loading");

//result variables
const search_result_div = document.getElementById("search_result");
const webscore_div = document.getElementById("web-score");
let webscore = 0;
const httpsBlock_div = document.getElementById("httpsBlock");
let httpsBlock;
const sslc_div = document.getElementById("sslc");
let sslc;
const authorcredntials_div = document.getElementById("acd");
let authorcredntials = 0;
const domainId_div = document.getElementById("domainId");
let domainId = 0;
const webAge_div = document.getElementById("age");
let webAge;

//details variables
const reputation_div = document.getElementById("reputation");
let reputation;
const website_type_div = document.getElementById("websiteType");
let website_type;
const DomainAge_div = document.getElementById("DomainAge");
let DomainAge;
const organization_div = document.getElementById("organization");
let organization;
const Country_div = document.getElementById("Country");
let Country;
const websiteName_div = document.getElementById("websiteName");
let websiteName;
const Reg_Web_div = document.getElementById("Reg-Web");
let Reg_Web;
const IP_div = document.getElementById("IP");
let IP;
const ssl_cert_div = document.getElementById("ssl-cert");
let ssl_cert;
const domainExtension_div = document.getElementById("domainExtension");
let domainExtension;
const alexaRank_div = document.getElementById("alexaRank");
let alexaRank;

//security variables
const malware_div = document.getElementById("malware");
let malware;
const phishing_div = document.getElementById("phishing");
let phishing;
const scam_div = document.getElementById("scam");
let scam;
const spam_div = document.getElementById("spam");
let spam;
const safe_Browsing_div = document.getElementById("safeBrowsing");
let safe_Browsing;

//registrant variables
const registrantName_div = document.getElementById("registrantName");
let registrantName;
const registrantOrganization_div = document.getElementById("registrantOrganization");
let registrantOrganization;
const registrantCountry_div = document.getElementById("registrantCountry");
let registrantCountry;
const registrantState_div = document.getElementById("registrantState");
let registrantState;
const registrantCity_div = document.getElementById("registrantCity");
let registrantCity;
const registrantStreet_div = document.getElementById("registrantStreet");
let registrantStreet;
const registrantPostalCode_div = document.getElementById("registrantPostalCode");
let registrantPostalCode;
const registrantPhone_div = document.getElementById("registrantPhone");
let registrantPhone;
const registrantEmail_div = document.getElementById("registrantEmail");
let registrantEmail;

//description variable
const description_div = document.getElementById("description");
let description;

//blank variable
let blank_div = document.getElementById("blank");

//button and enter function
document.getElementById("search_button").addEventListener("click", function () {
    const domain = domainInput_div.value.trim();
    console.log("Search button clicked, domain:", domain); // Log the domain
    getDetails(domain);
});

document.getElementById("search_content").addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        event.preventDefault();
        const domain = domainInput_div.value.trim();
        console.log("Enter key pressed, domain:", domain); // Log the domain
        getDetails(domain);
    }
});

async function getDetails(domain) {
    showLoadingDiv();
    webscore = 0; // Reset webscore
    clearOldData(); // Clear old data
    await getResult(domain);
    hideLoadingDiv();
    showResultDiv();
}

//search function
async function getResult(domain) {
    try {
        console.log("Fetching data for domain:", domain); // Log the domain before fetch
        const response = await fetch(`/analyze?domain=${domain}`);
        const data = await response.json();

        console.log("Received data:", data); // Log the received data

        if (!data || !data.whois.WhoisRecord) {
            search_result_div.style.display = "none";
            blank_div.style.display = "block";
            blank_div.innerHTML = `<p style='color: red;'>Error: No data received or invalid data structure</p>`;
        } else {
            search_result_div.style.display = "block";
            blank_div.style.display = "none";

            //summary update
            httpscertificate = data.security.data.attributes.last_https_certificate.cert_signature.signature;
            sslcertificate = data.security.data.attributes.last_https_certificate.serial_number;
            if (registrantPhone || registrantEmail) {
                authorcredntials = 1;
            } else {
                authorcredntials = 0;
            }
            if (websiteName || IP) {
                domainId = 1;
            } else {
                domainId = 0;
            }

            // Update details with fetched data
            reputation = data.reputation.data.attributes.reputation || "0";
            DomainAge = data.whois.WhoisRecord.domainAge || "N/A";
            alexaRank = data.security.data.attributes.popularity_ranks.Alexa.rank || "N/A";

            // Details
            organization = data.whois.WhoisRecord.registrant.organization || "N/A";
            website_type = data.security.data.attributes.categories.BitDefender || "N/A";
            Country = data.whois.WhoisRecord.registrant.country || "N/A";

            // Web details
            websiteName = data.whois.WhoisRecord.domainName || "N/A";
            domainExtension = data.whois.WhoisRecord.domainNameExt || "N/A";
            Reg_Web = data.whois.WhoisRecord.registrarName || "N/A";
            IP = data.whois.WhoisRecord.ips || "N/A";
            ssl_cert = data.security.data.attributes.last_https_certificate.serial_number || "N/A";

            // Description
            description = data.whois.WhoisRecord.description || "N/A";

            // Security details
            //malware
            if (data.security.data.attributes.last_analysis_results.Malwared.result === "clean") {
                malware = "Not Found";
            } else {  
                malware = "Found";
            }

            //phishing
            if (data.security.data.attributes.last_analysis_results.Phishtank.result === "clean") {
                phishing = "Not Found";
            } else {
                phishing = "Found";
            }

            //scam
            if (data.security.data.attributes.last_analysis_results.Scantitan.result === "clean") {
                scam = "Not Found";
            } else {
                scam = "Found";
            }

            //spam
            if (data.security.data.attributes.last_analysis_results.Spam404.result === "clean") { 
                spam = "Not Found";
            } else {
                spam = "Found";
            }

            //safe browsing
            if (
                data.security && 
                data.security.data && 
                data.security.data.attributes && 
                data.security.data.attributes.last_analysis_results && 
                data.security.data.attributes.last_analysis_results["Google Safebrowsing"] && 
                data.security.data.attributes.last_analysis_results["Google Safebrowsing"].result
            ) {
                if(data.security.data.attributes.last_analysis_results["Google Safebrowsing"].result === "clean"){
                    safe_Browsing = "Yes";
                }
                else{
                    safe_Browsing = "No";
                }
            } else {
                safe_Browsing = "Unknown"; // Handle missing data
            }

            // Registrant details
            registrantName = data.whois.WhoisRecord.registrant.name || "N/A";
            registrantOrganization = data.whois.WhoisRecord.registrant.organization || "N/A";
            registrantCountry = data.whois.WhoisRecord.registrant.country || "N/A";
            registrantState = data.whois.WhoisRecord.registrant.state || "N/A";
            registrantCity = data.whois.WhoisRecord.registrant.city || "N/A";
            registrantStreet = data.whois.WhoisRecord.registrant.street1 || "N/A";
            registrantPostalCode = data.whois.WhoisRecord.registrant.postalCode || "N/A";
            registrantPhone = data.whois.WhoisRecord.registrant.telephone || "N/A";
            registrantEmail = data.whois.WhoisRecord.contactEmail || "N/A";

            // Update DOM elements
            getAge(data.whois.WhoisRecord.createdDate);

            //key details
            reputation_div.innerHTML = `${reputation}`;
            DomainAge_div.innerHTML = `${DomainAge}`;
            website_type_div.innerHTML = `${website_type}`;
            alexaRank_div.innerHTML = `${alexaRank}`;

            //details
            organization_div.innerHTML = `${organization}`;
            Country_div.innerHTML = `${Country}`;

            //webdetails
            websiteName_div.innerHTML = `${websiteName}`;
            domainExtension_div.innerHTML = `${domainExtension}`;
            Reg_Web_div.innerHTML = `${Reg_Web}`;
            IP_div.innerHTML = `${IP}`;
            ssl_cert_div.innerHTML = `${ssl_cert}`;
            createDisc();

            //security
            malware_div.innerHTML = `${malware}`;
            phishing_div.innerHTML = `${phishing}`;
            scam_div.innerHTML = `${scam}`;
            spam_div.innerHTML = `${spam}`;
            safe_Browsing_div.innerHTML = `${safe_Browsing}`;

            //registrant
            registrantName_div.innerHTML = `${registrantName}`;
            registrantOrganization_div.innerHTML = `${registrantOrganization}`;
            registrantCountry_div.innerHTML = `${registrantCountry}`;
            registrantState_div.innerHTML = `${registrantState}`;
            registrantCity_div.innerHTML = `${registrantCity}`;
            registrantStreet_div.innerHTML = `${registrantStreet}`;
            registrantPostalCode_div.innerHTML = `${registrantPostalCode}`;
            registrantPhone_div.innerHTML = `${registrantPhone}`;
            registrantEmail_div.innerHTML = `${registrantEmail}`;
            webAge_div.innerHTML = `${webAge}`;

            //next update

            verifyHttp(domain);

            // Check for unsafe conditions
            checkSafety();
        }
    } catch (error) {
        console.error("Error fetching data:", error); // Log the error
        blank_div.innerHTML = `<p style='color: red;'>Error: ${error.message}</p>`;
    }
}

function getAge(regDate) {
    let currentDate = new Date();
    let reg = new Date(regDate);
    let newage = currentDate.getFullYear() - reg.getFullYear();
    if (currentDate.getMonth() < reg.getMonth() || (currentDate.getMonth() === reg.getMonth() && currentDate.getDate() < reg.getDate())) {
        newage--;
    }
    DomainAge = webAge = newage;
}

//web score function
function verifyHttp(domain) {
    const checks = {
        httpsBlock: httpscertificate !== "N/A",
        sslc: sslcertificate !== "N/A",
        authorCredentials: authorcredntials !== "N/A",
        domainId: domainId !== "N/A",
        webAge: webAge !== "N/A"
    };

    for (let key in checks) {
        if (checks[key]) {
            webscore += 20;
        }
    }

    httpsBlock_div.innerHTML = checks.httpsBlock ? "Found" : "Not Found";
    sslc_div.innerHTML = checks.sslc ? "Found" : "Not Found";
    authorcredntials_div.innerHTML = checks.authorCredentials ? "Found" : "Not Found";
    domainId_div.innerHTML = checks.domainId ? "Found" : "Not Found";
    webAge_div.innerHTML = checks.webAge ? `${webAge}` : "Not Found";
    webscore_div.innerHTML = `${webscore}`;
}

function hideResultDiv(){
    search_result_div.style.display = "none";
}

function showResultDiv(){
    search_result_div.style.display = "block";
}

function clearOldData() {
    // Clear summary data
    reputation_div.innerHTML = "";
    DomainAge_div.innerHTML = "";
    website_type_div.innerHTML = "";
    alexaRank_div.innerHTML = "";

    // Clear details data
    organization_div.innerHTML = "";
    Country_div.innerHTML = "";

    // Clear web details data
    websiteName_div.innerHTML = "";
    domainExtension_div.innerHTML = "";
    Reg_Web_div.innerHTML = "";
    IP_div.innerHTML = "";
    ssl_cert_div.innerHTML = "";
    description_div.innerHTML = "";

    // Clear security data
    malware_div.innerHTML = "";
    phishing_div.innerHTML = "";
    scam_div.innerHTML = "";
    spam_div.innerHTML = "";
    safe_Browsing_div.innerHTML = "";

    // Clear registrant data
    registrantName_div.innerHTML = "";
    registrantOrganization_div.innerHTML = "";
    registrantCountry_div.innerHTML = "";
    registrantState_div.innerHTML = "";
    registrantCity_div.innerHTML = "";
    registrantStreet_div.innerHTML = "";
    registrantPostalCode_div.innerHTML = "";
    registrantPhone_div.innerHTML = "";
    registrantEmail_div.innerHTML = "";
    webAge_div.innerHTML = "";
}

function showLoadingDiv(){
    loading_div.style.display = "flex";
}

function hideLoadingDiv(){
    loading_div.style.display = "none";
}

function checkSafety() {
    if(phishing === "Found" || scam === "Found" || spam === "Found" || malware === "Found" || safe_Browsing === "No"){
        alert("This website is not safe to visit");
        if(phishing === "Found"){
            alert("This website is phishing");
            webscore -= 15;
        }
        if(scam === "Found"){
            alert("This website is scam");
            webscore -= 15;
        }
        if(spam === "Found"){
            alert("This website is spam");
            webscore -= 15;
        }
        if(malware === "Found"){
            alert("This website is malware");
            webscore -= 15;
        }
        if(safe_Browsing === "No"){
            alert("This website is not safe to browse");
            webscore -= 15;
        }
    }

    if(webscore < 50){
        alert("This website is not safe to visit");
    }

    if(webscore === 100){
        alert("This website is safe to visit");
    }
}
function createDisc(){
    description = "The JavaScript script for website security analysis defines several key variables to assess and display a website’s security status, reputation, and registrant details. The search variables, such as httpscertificate and sslcertificate, store HTTPS and SSL-related information, ensuring that the website follows encryption standards. The result variables, including webscore, httpsBlock_div, and webAge_div, track the website’s overall security score and display relevant findings to the user. Various details variables like reputation, website_type, DomainAge, and alexaRank help categorize the website and determine its trustworthiness. The script also includes security variables such as malware, phishing, scam, and safe_Browsing to detect potential online threats using external security checks. Additionally, registrant variables like registrantName, registrantEmail, and registrantCountry store domain ownership details, providing insight into the website’s legitimacy. Lastly, the description variable holds a summary of the domain’s security status, while blank_div manages error displays. These variables collectively ensure a structured and comprehensive security assessment, allowing users to evaluate a website’s safety before interaction."
    description.innerHTML = "Description: " + description;

}
hideResultDiv();