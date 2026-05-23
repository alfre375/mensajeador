import QRCode from './clientLibraries/qr_esm.js'
async function generateQR(element, text, errorCorrectionLevel) {
    if (!text) {
        alert("Please enter text or URL");
        return;
    }

    element.innerHTML = "";

    try {
        const svgString = await QRCode.toString(text, {
            type: 'svg',
            errorCorrectionLevel: errorCorrectionLevel || 'H',
            margin: 2,
            color: {
                dark: '#000000',
                light: '#ffffff'
            }
        });
        
        element.innerHTML = svgString;
    } catch (err) {
        console.error(err);
    }
}

window.generateQR = generateQR;