from flask import Blueprint, send_from_directory, current_app

# Define el Blueprint para las rutas de PDFs
# No se especifica 'url_prefix' aquí, ya que la ruta '/pdfs/<filename>' lo define
# directamente para este Blueprint.
pdf_bp = Blueprint('pdfs', __name__)

# Ruta para servir archivos PDF desde la carpeta configurada en app.py
@pdf_bp.route('/pdfs/<filename>')
def serve_pdf(filename):
    # 'current_app' permite acceder a las configuraciones definidas en app.py,
    # como app.config['PDF_FOLDER'].
    return send_from_directory(current_app.config['PDF_FOLDER'], filename)