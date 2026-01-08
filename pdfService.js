const fs = require('fs');
const pdf = require('pdf-parse');

async function parseRoadmapPdf(filePath) {
    const dataBuffer = fs.readFileSync(filePath);
    try {
        const { PDFParse } = require('pdf-parse');

        // Convert Buffer to Uint8Array as required by this library version
        const uint8Array = new Uint8Array(dataBuffer);

        const instance = new PDFParse(uint8Array);
        const data = await instance.getText();

        // data might be string or object with text propery. 
        // Based on debug logs, getText returns the text content directly? 
        // Wait, standard getText returns plain text string usually.
        // I will assume it returns object with .text or string.
        // Let's safe check.
        const textContent = (typeof data === 'string') ? data : data.text;

        // Basic heuristic: split by newlines, filter empty or short lines
        // A real roadmap might have bullet points, numbers, etc.
        // We will look for lines starting with "Day", "Week", "-", "*", or numbers.

        const lines = textContent.split('\n');

        const sections = [];
        let currentSection = { section: "General", tasks: [] };
        let currentTask = null; // { task: string, details: string }

        // Regex helpers
        const sectionHeaderRegex = /^(Week|Phase|Month|Section|Chapter)\s+\d+/i;
        const taskItemRegex = /^(Day\s+\d+|Step\s+\d+|\d+[\).-]|\*|-|•)/i;

        for (const line of lines) {
            const cleanLine = line.trim();
            if (!cleanLine) continue;

            // Check for Section Header
            if (sectionHeaderRegex.test(cleanLine)) {
                // Push previous section if it has content
                if (currentSection.tasks.length > 0 || currentSection.section !== "General") {
                    // Push previous task if exists
                    if (currentTask) {
                        currentSection.tasks.push(currentTask);
                        currentTask = null;
                    }
                    sections.push(currentSection);
                }
                currentSection = { section: cleanLine, tasks: [] };
                continue;
            }

            // Check for Task Item
            if (taskItemRegex.test(cleanLine)) {
                // Save previous task
                if (currentTask) {
                    currentSection.tasks.push(currentTask);
                }
                currentTask = { task: cleanLine, details: '' };
            } else {
                // Detail line
                if (currentTask) {
                    currentTask.details += (currentTask.details ? " " : "") + cleanLine;
                } else {
                    // Orphan text implies task if we don't have one, or continuation of section desc?
                    // We'll treat as task if generic
                    currentTask = { task: cleanLine, details: '' };
                }
            }
        }

        // Final cleanup
        if (currentTask) {
            currentSection.tasks.push(currentTask);
        }
        if (currentSection.tasks.length > 0 || currentSection.section !== "General") {
            sections.push(currentSection);
        }

        // Ensure we send back at least something
        const finalData = sections.length > 0 ? sections : [{ section: "General", tasks: [{ task: "Could not parse tasks correctly", details: textContent.substring(0, 50) }] }];

        return finalData;
    } catch (err) {
        console.error(err);
        throw err;
    }
}

module.exports = { parseRoadmapPdf };
