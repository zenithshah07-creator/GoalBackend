const lib = require('pdf-parse');
console.log('Lib keys:', Object.keys(lib));
if (lib.PDFParse) {
    console.log('lib.PDFParse type:', typeof lib.PDFParse);
}
// try to see if I can call it
const fs = require('fs');
// Mocking a buffer
const buffer = Buffer.from('test');
try {
    if (typeof lib === 'function') console.log('lib is function');
    if (typeof lib.default === 'function') console.log('lib.default is function');
} catch (e) {
    console.error(e);
}
