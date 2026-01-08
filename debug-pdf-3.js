const { PDFParse } = require('pdf-parse');
const fs = require('fs');

async function test() {
    // create a dummy buffer
    const buffer = Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 44 >>\nstream\nBT\n/F1 12 Tf\n72 712 Td\n(Hello World) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000157 00000 n \n0000000246 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n341\n%%EOF');

    try {
        console.log('Trying new PDFParse()...');
        const instance = new PDFParse(buffer);
        console.log('Instance created.');
        console.log('Instance keys:', Object.keys(instance));

        // Check if instance is a promise ?? unlikely
        if (instance instanceof Promise) {
            console.log('Instance is a Promise');
            const res = await instance;
            console.log('Result:', res);
        } else {
            console.log('Instance is NOT a Promise');
            // look for methods
            console.log('Prototype keys:', Object.getOwnPropertyNames(Object.getPrototypeOf(instance)));
        }

    } catch (e) {
        console.error('Error with new:', e);
    }
}

test();
