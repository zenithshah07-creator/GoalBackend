const { PDFParse } = require('pdf-parse');
const fs = require('fs');

async function test() {
    const buffer = Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 44 >>\nstream\nBT\n/F1 12 Tf\n72 712 Td\n(Hello World) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000157 00000 n \n0000000246 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n341\n%%EOF');

    try {
        const instance = new PDFParse(buffer);
        console.log('Calling getText()...');
        const text = await instance.getText();
        console.log('Text result:', text);
    } catch (e) {
        console.error('Error calling getText:', e);
    }
}

test();
