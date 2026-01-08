const pdf = require('pdf-parse');
console.log('Type of pdf:', typeof pdf);
console.log('Is array?', Array.isArray(pdf));
console.log('Keys:', Object.keys(pdf));
if (typeof pdf === 'object') {
    // try to see if it has a default
    console.log('pdf.default:', pdf.default);
}
