halo-report-generator
=====================

Generate HTML, PDF reports for CSM and SVA Halo modules

###Required Modules:
* xhtml2pdf or pdfkit for PDF output
* markdown

###Caveats:
* If configured to output to PDF, will attempt to load xhtml2pdf and pdfkit.  At least one required.  If both are loadable, pdfkit is preferred.  If pdfkit is installed and wkhtml2pdf is not installed, it will error out.
* If configured to use a proxy and output to PDF, you must use a local logo file.
