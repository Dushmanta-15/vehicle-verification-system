# routes/admin_routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from app.models.admin import Admin
from app.models.user import User
from app.models.vehicle import Vehicle
from app import db
from functools import wraps
from datetime import datetime
import json
from sqlalchemy import func
from datetime import datetime, timedelta
from app.utils import AnomalyDetection
from datetime import datetime, timedelta
from calendar import month_name
from flask import jsonify
from flask import send_file, make_response, current_app
from datetime import datetime, timedelta
from calendar import month_name
import pandas as pd
import io
import pdfkit
from sqlalchemy import func
from app.utils import VehicleBlockchainManager
from flask import send_file
import json
import io
from datetime import datetime

# Change this line to include url_prefix
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function

# Remove '/admin' from all routes since it's in the url_prefix
@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_id'] = admin.id
            admin.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('admin.dashboard'))
        
        flash('Invalid credentials')
    return render_template('admin/login.html')

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    stats = {
        'total_users': User.query.count(),
        'total_vehicles': Vehicle.query.count(),
        'new_users_today': User.query.filter(
            User.created_at >= datetime.utcnow().date()
        ).count(),
        'new_vehicles_today': Vehicle.query.filter(
            Vehicle.created_at >= datetime.utcnow().date()
        ).count()
    }
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_vehicles = Vehicle.query.order_by(Vehicle.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                         stats=stats,
                         recent_users=recent_users,
                         recent_vehicles=recent_vehicles)

@admin_bp.route('/users')
@admin_required
def manage_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=10)
    return render_template('admin/users.html', users=users)

@admin_bp.route('/vehicles')
@admin_required
def manage_vehicles():
    page = request.args.get('page', 1, type=int)
    vehicles = Vehicle.query.paginate(page=page, per_page=10)
    return render_template('admin/vehicles.html', vehicles=vehicles)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    Vehicle.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('User and associated vehicles deleted successfully')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/vehicles/<int:vehicle_id>/delete', methods=['POST'])
@admin_required
def delete_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    db.session.delete(vehicle)
    db.session.commit()
    flash('Vehicle deleted successfully')
    return redirect(url_for('admin.manage_vehicles'))

# Add these to your existing admin_routes.py file

from datetime import datetime, timedelta
from calendar import month_name
from flask import jsonify

@admin_bp.route('/reports')
@admin_required
def reports():
    """
    Reports page showing registration statistics
    """
    # Get summary statistics
    summary = {
        'total_users': User.query.count(),
        'total_vehicles': Vehicle.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'new_vehicles_today': Vehicle.query.filter(
            Vehicle.created_at >= datetime.utcnow().date()
        ).count()
    }
    
    # Get monthly registrations for the current year
    monthly_registrations = get_monthly_registrations(datetime.utcnow().year)
    
    # Get recent users and vehicles
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_vehicles = Vehicle.query.order_by(Vehicle.created_at.desc()).limit(5).all()
    
    return render_template('admin/reports.html',
                         summary=summary,
                         monthly_registrations=monthly_registrations,
                         recent_users=recent_users,
                         recent_vehicles=recent_vehicles)

@admin_bp.route('/reports/export-excel')
@admin_required
def export_excel():
    """
    Export registration data to Excel
    """
    # Create in-memory Excel file
    output = io.BytesIO()
    
    # Create data
    summary_data = get_summary_data()
    monthly_data = get_monthly_registrations(datetime.utcnow().year)
    users_data = get_users_data()
    vehicles_data = get_vehicles_data()
    
    # Convert to pandas DataFrames
    summary_df = pd.DataFrame([summary_data])
    monthly_df = pd.DataFrame(monthly_data)
    users_df = pd.DataFrame(users_data)
    vehicles_df = pd.DataFrame(vehicles_data)
    
    # Write to Excel
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        # Write summary sheet
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        # Write monthly registrations sheet
        monthly_df.to_excel(writer, sheet_name='Monthly Registrations', index=False)
        
        # Write users sheet
        users_df.to_excel(writer, sheet_name='Users', index=False)
        
        # Write vehicles sheet
        vehicles_df.to_excel(writer, sheet_name='Vehicles', index=False)
        
        # Auto-adjust column widths
        for sheet_name in writer.sheets:
            worksheet = writer.sheets[sheet_name]
            for i, col in enumerate(monthly_df.columns):
                # Find the maximum length in the column
                max_len = max(
                    monthly_df[col].astype(str).map(len).max(),
                    len(col)
                ) + 2  # Add some padding
                worksheet.set_column(i, i, max_len)
    
    # Reset file pointer
    output.seek(0)
    
    # Generate the response
    today = datetime.utcnow().strftime('%Y-%m-%d')
    filename = f'Vehicle_Verification_Report_{today}.xlsx'
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

@admin_bp.route('/reports/export-pdf')
@admin_required
def export_pdf():
    """
    Export registration data to PDF
    """
    # Get data for the PDF
    summary_data = get_summary_data()
    monthly_data = get_monthly_registrations(datetime.utcnow().year)
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_vehicles = Vehicle.query.order_by(Vehicle.created_at.desc()).limit(5).all()
    
    # Format user and vehicle data for the template
    formatted_users = []
    for user in recent_users:
        formatted_users.append({
            'username': user.username,
            'email': user.email,
            'created_at': user.created_at.strftime('%d-%m-%Y')
        })
    
    formatted_vehicles = []
    for vehicle in recent_vehicles:
        formatted_vehicles.append({
            'vehicle_number': vehicle.vehicle_number,
            'owner_name': vehicle.owner_name,
            'created_at': vehicle.created_at.strftime('%d-%m-%Y')
        })
    
    # Prepare data for the template
    data = {
        'report_date': datetime.utcnow().strftime('%d-%m-%Y'),
        'summary': summary_data,
        'monthly_registrations': monthly_data,
        'recent_users': formatted_users,
        'recent_vehicles': formatted_vehicles
    }
    
    # Render template
    html = render_template('admin/pdf/report.html', data=data)
    
    # Generate PDF
    try:
        # For Windows
        config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")
        pdf = pdfkit.from_string(html, False, configuration=config)
    except Exception as e:
        # Fallback for other systems
        try:
            pdf = pdfkit.from_string(html, False)
        except Exception as e:
            current_app.logger.error(f"Error generating PDF: {str(e)}")
            flash("Error generating PDF. Please make sure wkhtmltopdf is installed.", "error")
            return redirect(url_for('admin.reports'))
    
    # Create response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=Vehicle_Verification_Report.pdf'
    
    return response

# Helper Functions
def get_monthly_registrations(year):
    """
    Get monthly user and vehicle registrations for a specific year
    """
    from sqlalchemy import func, extract
    
    # Get user registrations per month
    user_registrations = db.session.query(
        extract('month', User.created_at).label('month'),
        func.count(User.id).label('count')
    ).filter(
        extract('year', User.created_at) == year
    ).group_by(
        extract('month', User.created_at)
    ).all()
    
    # Convert to dictionary for easy lookup
    user_dict = {int(month.month): month.count for month in user_registrations}
    
    # Get vehicle registrations per month
    vehicle_registrations = db.session.query(
        extract('month', Vehicle.created_at).label('month'),
        func.count(Vehicle.id).label('count')
    ).filter(
        extract('year', Vehicle.created_at) == year
    ).group_by(
        extract('month', Vehicle.created_at)
    ).all()
    
    # Convert to dictionary for easy lookup
    vehicle_dict = {int(month.month): month.count for month in vehicle_registrations}
    
    # Combine data
    monthly_data = []
    for month_num in range(1, 13):
        # Get month name
        month_name_str = month_name[month_num]
        
        monthly_data.append({
            'month': month_name_str,
            'users_registered': user_dict.get(month_num, 0),
            'vehicles_registered': vehicle_dict.get(month_num, 0)
        })
    
    return monthly_data

def get_summary_data():
    """
    Get summary statistics for the system
    """
    # Current date
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)
    
    # Calculate statistics
    total_users = User.query.count()
    total_vehicles = Vehicle.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    new_users_today = User.query.filter(
        User.created_at >= today
    ).count()
    new_vehicles_today = Vehicle.query.filter(
        Vehicle.created_at >= today
    ).count()
    new_users_yesterday = User.query.filter(
        User.created_at >= yesterday,
        User.created_at < today
    ).count()
    new_vehicles_yesterday = Vehicle.query.filter(
        Vehicle.created_at >= yesterday,
        Vehicle.created_at < today
    ).count()
    
    # Return summary data
    return {
        'Total Users': total_users,
        'Total Vehicles': total_vehicles,
        'Active Users': active_users,
        'New Users Today': new_users_today,
        'New Vehicles Today': new_vehicles_today,
        'New Users Yesterday': new_users_yesterday,
        'New Vehicles Yesterday': new_vehicles_yesterday
    }

def get_users_data():
    """
    Get user registration data
    """
    users = User.query.order_by(User.created_at.desc()).all()
    
    users_data = []
    for user in users:
        users_data.append({
            'Username': user.username,
            'Email': user.email,
            'Full Name': f"{user.first_name} {user.last_name}",
            'Mobile': user.mobile_number if hasattr(user, 'mobile_number') else '',
            'Active': 'Yes' if user.is_active else 'No',
            'Registered On': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return users_data

def get_vehicles_data():
    """
    Get vehicle registration data
    """
    vehicles = Vehicle.query.order_by(Vehicle.created_at.desc()).all()
    
    vehicles_data = []
    for vehicle in vehicles:
        owner = User.query.get(vehicle.user_id)
        owner_name = owner.username if owner else 'Unknown'
        
        vehicles_data.append({
            'Vehicle Number': vehicle.vehicle_number,
            'Owner Name': vehicle.owner_name,
            'Owner Username': owner_name,
            'Model': vehicle.model if hasattr(vehicle, 'model') else '',
            'Year': vehicle.year if hasattr(vehicle, 'year') else '',
            'Registered On': vehicle.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return vehicles_data

@admin_bp.route('/settings')
@admin_required
def settings():
    return render_template('admin/settings.html')

@admin_bp.route('/logout')
def logout():
    session.pop('admin_id', None)
    return redirect(url_for('admin.login'))

# Add a test route
@admin_bp.route('/test')
def test():
    return "Admin routes are working!"

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        if request.form.get('password'):
            user.password_hash = generate_password_hash(request.form.get('password'))
        db.session.commit()
        flash('User updated successfully')
        return redirect(url_for('admin.manage_users'))
    return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/vehicles/<int:vehicle_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    if request.method == 'POST':
        vehicle.vehicle_number = request.form.get('vehicle_number')
        vehicle.owner_name = request.form.get('owner_name')
        vehicle.model = request.form.get('model')
        vehicle.year = request.form.get('year')
        db.session.commit()
        flash('Vehicle updated successfully')
        return redirect(url_for('admin.manage_vehicles'))
    return render_template('admin/edit_vehicle.html', vehicle=vehicle)

@admin_bp.route('/security')
@admin_required
def security_dashboard():
    """
    Security dashboard showing anomaly detection results and security metrics
    """
    from app.utils import AnomalyDetection
    from app.models.request_log import RequestLog
    from app.models.verification_attempt import VerificationAttempt
    
    # Force the session to refresh to ensure we get fresh data
    db.session.expire_all()
    
    # Use 1 hour timeframe
    time_threshold = datetime.utcnow() - timedelta(days=60)
    
    # ===== ADD THIS DEBUG SECTION =====
    print("\n" + "="*50)
    print("🔍 SECURITY DASHBOARD DEBUG INFO")
    print("="*50)
    print(f"📅 Time threshold: {time_threshold}")
    print(f"📅 Current time: {datetime.utcnow()}")
    
    # Check if RequestLog table exists and has data
    try:
        total_requests_ever = RequestLog.query.count()
        print(f"📊 Total requests in database: {total_requests_ever}")
        
        if total_requests_ever > 0:
            # Get sample of recent requests
            recent_sample = RequestLog.query.order_by(RequestLog.created_at.desc()).limit(5).all()
            print("📝 Recent request samples:")
            for req in recent_sample:
                print(f"   - {req.created_at} | {req.method} {req.endpoint} | Response: {req.response_time_ms}ms | Anomaly: {req.has_anomaly}")
        
        # Check requests in our time window
        requests_in_window = RequestLog.query.filter(
            RequestLog.created_at >= time_threshold
        ).count()
        print(f"📈 Requests in time window (last 7 days): {requests_in_window}")
        
        # Check anomalous requests
        total_anomalies_ever = RequestLog.query.filter(RequestLog.has_anomaly == True).count()
        print(f"🚨 Total anomalies ever: {total_anomalies_ever}")
        
        anomalies_in_window = RequestLog.query.filter(
            RequestLog.has_anomaly == True,
            RequestLog.created_at >= time_threshold
        ).count()
        print(f"🚨 Anomalies in time window: {anomalies_in_window}")
        
        # Check response times
        response_times_sample = db.session.query(RequestLog.response_time_ms).filter(
            RequestLog.response_time_ms.isnot(None)
        ).limit(10).all()
        
        if response_times_sample:
            times = [r[0] for r in response_times_sample if r[0] is not None]
            print(f"⏱️  Sample response times: {times}")
            
            # Calculate average
            avg_time = db.session.query(func.avg(RequestLog.response_time_ms)).filter(
                RequestLog.created_at >= time_threshold,
                RequestLog.response_time_ms.isnot(None)
            ).scalar()
            print(f"⏱️  Average response time (7 days): {avg_time}")
        else:
            print("⏱️  No response times found in database")
            
    except Exception as e:
        print(f"❌ Error checking RequestLog: {str(e)}")
    
    # Check VerificationAttempt table
    try:
        total_verifications = VerificationAttempt.query.count()
        print(f"🔐 Total verification attempts: {total_verifications}")
        
        if total_verifications > 0:
            failed_verifications = VerificationAttempt.query.filter(
                VerificationAttempt.is_successful == False
            ).count()
            print(f"🔐 Total failed verifications: {failed_verifications}")
            
            # Sample verification attempts
            verification_sample = VerificationAttempt.query.order_by(VerificationAttempt.created_at.desc()).limit(3).all()
            print("🔐 Recent verification samples:")
            for ver in verification_sample:
                print(f"   - {ver.created_at} | Type: {ver.verification_type} | Success: {ver.is_successful}")
    except Exception as e:
        print(f"❌ Error checking VerificationAttempt: {str(e)}")
    
    print("="*50)
    print("🔍 END DEBUG INFO")
    print("="*50 + "\n")
    # ===== END DEBUG SECTION =====
    
    # Get statistical anomaly detection results
    statistical_anomalies = AnomalyDetection.detect_registration_spikes(hours=1, force_refresh=True)
    
    # Get verification statistics
    verification_stats = {
        'total_attempts': VerificationAttempt.query.filter(
            VerificationAttempt.created_at >= time_threshold
        ).with_entities(func.count(VerificationAttempt.id)).scalar(),
        'successful_attempts': VerificationAttempt.query.filter(
            VerificationAttempt.is_successful == True,
            VerificationAttempt.created_at >= time_threshold
        ).with_entities(func.count(VerificationAttempt.id)).scalar(),
        'failed_attempts': VerificationAttempt.query.filter(
            VerificationAttempt.is_successful == False,
            VerificationAttempt.created_at >= time_threshold
        ).with_entities(func.count(VerificationAttempt.id)).scalar(),
    }
    
    # Initialize with default values to avoid None issues
    verification_stats['total_attempts'] = verification_stats['total_attempts'] or 0
    verification_stats['successful_attempts'] = verification_stats['successful_attempts'] or 0
    verification_stats['failed_attempts'] = verification_stats['failed_attempts'] or 0
    
    if verification_stats['total_attempts'] > 0:
        verification_stats['success_rate'] = (verification_stats['successful_attempts'] / verification_stats['total_attempts']) * 100
    else:
        verification_stats['success_rate'] = 0
    
    # Get recent failed verifications
    recent_failures = VerificationAttempt.query.filter(
        VerificationAttempt.is_successful == False,
        VerificationAttempt.created_at >= time_threshold
    ).order_by(
        VerificationAttempt.created_at.desc()
    ).limit(10).all()
    
    # Clear any cached results for request statistics
    db.session.commit()
    
    # Get request statistics
    request_stats = {
        'total_requests': RequestLog.query.filter(
            RequestLog.created_at >= time_threshold
        ).with_entities(func.count(RequestLog.id)).scalar() or 0,
        'anomalous_requests': RequestLog.query.filter(
            RequestLog.has_anomaly == True,
            RequestLog.created_at >= time_threshold
        ).with_entities(func.count(RequestLog.id)).scalar() or 0,
    }
    
    # Get average response time
    avg_response_time = db.session.query(func.avg(RequestLog.response_time_ms)).filter(
        RequestLog.created_at >= time_threshold
    ).scalar() or 0
    request_stats['avg_response_time'] = float(avg_response_time)
    
    # Get recent anomalous requests
    recent_anomalies = RequestLog.query.filter(
        RequestLog.has_anomaly == True,
        RequestLog.created_at >= time_threshold
    ).order_by(
        RequestLog.created_at.desc()
    ).limit(10).all()
    
    # Calculate total recent anomalies for ML section
    total_recent_anomalies = verification_stats['failed_attempts'] + request_stats['anomalous_requests']
    
    # Try to get ML anomalies, but if it fails, create a simple version
    try:
        ml_anomalies = AnomalyDetection.detect_ml_anomalies()
    except Exception as e:
        print(f"Error in ML detection: {str(e)}")
        ml_anomalies = {
            'has_anomaly': total_recent_anomalies > 0,
            'detection_method': 'fallback',
            'model_info': {
                'algorithm': 'Isolation Forest',
                'days_analyzed': 30,
            },
            'total_anomalies_found': total_recent_anomalies,
            'anomaly_details': []
        }
    
    # Manually update the total anomalies found to match the actual recent anomalies
    ml_anomalies['total_anomalies_found'] = total_recent_anomalies
    ml_anomalies['has_anomaly'] = total_recent_anomalies > 0
    
    # Add timestamp for debugging
    current_time = datetime.utcnow()
    
    return render_template(
        'admin/security.html',
        registration_anomalies=statistical_anomalies,
        ml_anomalies=ml_anomalies,
        verification_stats=verification_stats,
        request_stats=request_stats,
        recent_failures=recent_failures,
        recent_anomalies=recent_anomalies,
        last_refresh=current_time,
        is_ai_powered=True
    )
@admin_bp.route('/security/verification-attempts')
@admin_required
def verification_attempts():
    """
    List of verification attempts with filtering and sorting options
    """
    from app.models.verification_attempt import VerificationAttempt
    
    page = request.args.get('page', 1, type=int)
    success_filter = request.args.get('success')
    type_filter = request.args.get('type')
    
    # Build query with filters
    query = VerificationAttempt.query
    
    if success_filter == 'success':
        query = query.filter_by(is_successful=True)
    elif success_filter == 'failure':
        query = query.filter_by(is_successful=False)
        
    if type_filter:
        query = query.filter_by(verification_type=type_filter)
    
    # Get paginated results
    attempts = query.order_by(VerificationAttempt.created_at.desc()).paginate(
        page=page, per_page=20
    )
    
    # Get unique verification types for filter dropdown
    verification_types = db.session.query(
        VerificationAttempt.verification_type
    ).distinct().all()
    
    verification_types = [v[0] for v in verification_types]
    
    return render_template(
        'admin/verification_attempts.html',
        attempts=attempts,
        verification_types=verification_types,
        success_filter=success_filter,
        type_filter=type_filter,
        max=max,  # Add the max function
        min=min  # Add the min function
    )

@admin_bp.route('/security/request-logs')
@admin_required
def request_logs():
    """
    List of API request logs with filtering and sorting options
    """
    from app.models.request_log import RequestLog
    
    page = request.args.get('page', 1, type=int)
    anomaly_filter = request.args.get('anomaly')
    method_filter = request.args.get('method')
    
    # Build query with filters
    query = RequestLog.query
    
    if anomaly_filter == 'yes':
        query = query.filter_by(has_anomaly=True)
    elif anomaly_filter == 'no':
        query = query.filter_by(has_anomaly=False)
        
    if method_filter:
        query = query.filter_by(method=method_filter)
    
    # Get paginated results
    logs = query.order_by(RequestLog.created_at.desc()).paginate(
        page=page, per_page=20
    )
    
    # Get unique HTTP methods for filter dropdown
    methods = db.session.query(RequestLog.method).distinct().all()
    methods = [m[0] for m in methods]
    
    return render_template(
        'admin/request_logs.html',
        logs=logs,
        methods=methods,
        anomaly_filter=anomaly_filter,
        method_filter=method_filter
    )

# ADD NEW ROUTE FOR DELETING ANOMALIES
@admin_bp.route('/security/delete-anomalies', methods=['POST'])
@admin_required
def delete_anomalies():
    """
    Delete all anomalies and failed verification attempts
    """
    try:
        # Delete all failed verification attempts
        from app.models.verification_attempt import VerificationAttempt
        failed_attempts = VerificationAttempt.query.filter_by(is_successful=False).all()
        failed_count = len(failed_attempts)
        
        for attempt in failed_attempts:
            db.session.delete(attempt)
        
        # Delete all anomalous requests
        from app.models.request_log import RequestLog
        anomalous_requests = RequestLog.query.filter_by(has_anomaly=True).all()
        anomalies_count = len(anomalous_requests)
        
        for request in anomalous_requests:
            db.session.delete(request)
        
        # Commit the changes
        db.session.commit()
        
        # Return success response
        from flask import jsonify
        return jsonify({
            'status': 'success',
            'message': f'Successfully deleted {failed_count} failed verifications and {anomalies_count} anomalous requests',
            'deleted_count': failed_count + anomalies_count
        }), 200
        
    except Exception as e:
        # Log the error
        import traceback
        print(f"Error deleting anomalies: {str(e)}")
        print(traceback.format_exc())
        
        # Rollback the transaction
        db.session.rollback()
        
        # Return error response
        from flask import jsonify
        return jsonify({
            'status': 'error',
            'message': f'Error deleting anomalies: {str(e)}'
        }), 500


@admin_bp.route('/api/security/anomalies')
@admin_required
def api_security_anomalies():
    """
    API endpoint that returns current anomaly detection results and dashboard data
    """
    from app.utils import AnomalyDetection
    from app.models.verification_attempt import VerificationAttempt
    from app.models.request_log import RequestLog
    from datetime import datetime, timedelta
    from flask import jsonify, current_app
    from sqlalchemy import func
    import numpy as np
    import json
    
    class NumpyEncoder(json.JSONEncoder):
        """ Special json encoder for numpy types """
        def default(self, obj):
            if isinstance(obj, (np.integer, np.int32, np.int64)):
                return int(obj)
            elif isinstance(obj, (np.floating, np.float32, np.float64)):
                return float(obj)
            elif isinstance(obj, (np.ndarray,)):
                return obj.tolist()
            elif isinstance(obj, (np.bool_)):
                return bool(obj)
            return json.JSONEncoder.default(self, obj)
    
    # Using 1 hour timeframe
    time_threshold = datetime.utcnow() - timedelta(days=60)
    
    try:
        # Clear any existing session cache to ensure fresh queries
        db.session.commit()
        
        # Get current verification statistics
        verification_stats = {
            'total_attempts': VerificationAttempt.query.filter(
                VerificationAttempt.created_at >= time_threshold
            ).count(),
            'successful_attempts': VerificationAttempt.query.filter(
                VerificationAttempt.is_successful == True,
                VerificationAttempt.created_at >= time_threshold
            ).count(),
            'failed_attempts': VerificationAttempt.query.filter(
                VerificationAttempt.is_successful == False,
                VerificationAttempt.created_at >= time_threshold
            ).count(),
        }
        
        # Calculate success rate
        if verification_stats['total_attempts'] > 0:
            verification_stats['success_rate'] = (
                verification_stats['successful_attempts'] / verification_stats['total_attempts']
            ) * 100
        else:
            verification_stats['success_rate'] = 0
        
        # Get statistical anomalies
        statistical_anomalies = AnomalyDetection.detect_registration_spikes(hours=1)
        
        # Get ML-based anomalies
        try:
            ml_anomalies = AnomalyDetection.detect_ml_anomalies()
        except Exception as e:
            print(f"ML anomaly detection error in API: {str(e)}")
            ml_anomalies = {'has_anomaly': False, 'error': str(e)}
        
        # Convert any NumPy bool_ to Python bool
        for key, value in statistical_anomalies.items():
            if isinstance(value, np.bool_):
                statistical_anomalies[key] = bool(value)
            
            # Also check nested dictionaries
            if isinstance(value, dict):
                for k, v in value.items():
                    if isinstance(v, np.bool_):
                        value[k] = bool(v)
        
        # API request statistics
        request_stats = {
            'total_requests': RequestLog.query.filter(
                RequestLog.created_at >= time_threshold
            ).count(),
            'anomalous_requests': RequestLog.query.filter(
                RequestLog.has_anomaly == True,
                RequestLog.created_at >= time_threshold
            ).count(),
        }
        
        # Average response time
        avg_response_time = db.session.query(
            func.avg(RequestLog.response_time_ms)
        ).filter(
            RequestLog.created_at >= time_threshold
        ).scalar() or 0
        request_stats['avg_response_time'] = float(avg_response_time) if avg_response_time is not None else 0
        
        # Recent failures
        recent_failures = VerificationAttempt.query.filter(
            VerificationAttempt.is_successful == False,
            VerificationAttempt.created_at >= time_threshold
        ).order_by(
            VerificationAttempt.created_at.desc()
        ).limit(10).all()
        
        # Format recent failures
        recent_failures_data = []
        for attempt in recent_failures:
            recent_failures_data.append({
                'verification_type': attempt.verification_type,
                'failure_reason': attempt.failure_reason,
                'created_at': attempt.created_at.isoformat() if attempt.created_at else None
            })
        
        # Recent anomalies
        recent_anomalies = RequestLog.query.filter(
            RequestLog.has_anomaly == True,
            RequestLog.created_at >= time_threshold
        ).order_by(
            RequestLog.created_at.desc()
        ).limit(10).all()
        
        # Format recent anomalies
        recent_anomalies_data = []
        for log in recent_anomalies:
            recent_anomalies_data.append({
                'method': log.method,
                'endpoint': log.endpoint,
                'anomaly_details': log.anomaly_details,
                'ip_address': log.ip_address,
                'created_at': log.created_at.isoformat() if log.created_at else None
            })
        
        # Determine if any anomalies exist (convert to standard Python bool)
        has_anomalies = bool(
            statistical_anomalies.get('has_anomaly', False) or 
            ml_anomalies.get('has_anomaly', False) or
            verification_stats['failed_attempts'] > 0 or
            request_stats['anomalous_requests'] > 0
        )
        
        response_data = {
            'statistical_anomalies': statistical_anomalies,
            'ml_anomalies': ml_anomalies,
            'verification_stats': verification_stats,
            'request_stats': request_stats,
            'recent_failures': recent_failures_data,
            'recent_anomalies': recent_anomalies_data,
            'has_anomalies': has_anomalies,
            'timestamp': datetime.utcnow().isoformat(),
            'is_ai_powered': True
        }
        
        # Use the custom JSON encoder for NumPy types
        return current_app.response_class(
            response=json.dumps(response_data, cls=NumpyEncoder),
            status=200,
            mimetype='application/json'
        )
    
    except Exception as e:
        import traceback
        print(f"Error in api_security_anomalies: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@admin_bp.route('/blockchain')
@admin_required
def blockchain_dashboard():
    """
    Simple blockchain monitoring dashboard
    """
    try:
        # Initialize blockchain manager
        blockchain_manager = VehicleBlockchainManager()
        
        # Get real blockchain statistics
        blockchain_stats = blockchain_manager.verify_system_integrity()
        
        # Get recent transactions from actual blockchain
        recent_transactions = blockchain_manager.blockchain.get_transaction_history()[-10:]
        
        # Format recent transactions for display
        formatted_transactions = []
        for tx in recent_transactions:
            formatted_transactions.append({
                'tx_id': tx.get('tx_id', 'Unknown'),
                'type': tx.get('type', 'unknown'),
                'block_index': tx.get('block_index', 0),
                'timestamp': tx.get('timestamp', ''),
                'data': tx.get('data', {})
            })
        
        # Get audit trail (recent activity)
        audit_trail = []
        for tx in recent_transactions[-5:]:  # Last 5 for audit trail
            description = "Unknown activity"
            action = "unknown"
            
            if tx.get('type') == 'verification_attempt':
                data = tx.get('data', {})
                if data.get('is_successful'):
                    description = f"Successful {data.get('verification_type', 'unknown')} verification"
                    action = "verified"
                else:
                    description = f"Failed {data.get('verification_type', 'unknown')} verification"
                    action = "failed"
            elif tx.get('type') == 'vehicle_registration':
                data = tx.get('data', {})
                description = f"Vehicle {data.get('vehicle_number', 'unknown')} registered"
                action = "created"
            elif tx.get('type') == 'certificate_issuance':
                description = "Certificate issued"
                action = "created"
            
            # Format timestamp
            timestamp = tx.get('timestamp', '')
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                formatted_time = dt.strftime('%H:%M %p')
            except:
                formatted_time = timestamp[:10] if timestamp else 'Unknown'
            
            audit_trail.append({
                'description': description,
                'action': action,
                'timestamp': formatted_time,
                'block_number': tx.get('block_index', 0),
                'hash': tx.get('tx_id', 'Unknown')[:50] + '...' if tx.get('tx_id') else 'Unknown'
            })
        
        # Reverse audit trail to show most recent first
        audit_trail.reverse()
        
        # Last verification time
        last_verification_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return render_template('admin/blockchain.html',
                             blockchain_stats=blockchain_stats,
                             recent_transactions=formatted_transactions,
                             audit_trail=audit_trail,
                             last_verification_time=last_verification_time)
    
    except Exception as e:
        print(f"Error in blockchain dashboard: {str(e)}")
        # Fallback to mock data if there's an error
        blockchain_stats = {
            'blockchain_valid': False,
            'total_blocks': 0,
            'total_transactions': 0,
            'verification_attempts': 0,
            'vehicle_registrations': 0,
            'certificate_issuances': 0,
            'last_block_hash': 'Error loading blockchain'
        }
        
        return render_template('admin/blockchain.html',
                             blockchain_stats=blockchain_stats,
                             recent_transactions=[],
                             audit_trail=[],
                             last_verification_time='Error',
                             error_message=str(e))

@admin_bp.route('/blockchain/verify-integrity', methods=['POST'])
@admin_required
def verify_blockchain_integrity():
    """
    Verify blockchain integrity using the simple blockchain
    """
    try:
        blockchain_manager = VehicleBlockchainManager()
        integrity_report = blockchain_manager.verify_system_integrity()
        
        return jsonify(integrity_report)
        
    except Exception as e:
        print(f"Error verifying blockchain integrity: {str(e)}")
        return jsonify({
            'blockchain_valid': False,
            'error': str(e),
            'total_blocks': 0,
            'total_transactions': 0
        }), 500

@admin_bp.route('/blockchain/export')
@admin_required
def export_blockchain():
    """
    Export blockchain data as JSON
    """
    try:
        blockchain_manager = VehicleBlockchainManager()
        
        # Get complete blockchain data
        blockchain_data = {
            'metadata': {
                'export_date': datetime.utcnow().isoformat(),
                'total_blocks': len(blockchain_manager.blockchain.chain),
                'blockchain_version': '1.0.0',
                'network_type': 'private_simple'
            },
            'blocks': [block.to_dict() for block in blockchain_manager.blockchain.chain],
            'integrity_check': {
                'valid': blockchain_manager.blockchain.verify_integrity(),
                'last_verified': datetime.utcnow().isoformat()
            }
        }
        
        # Convert to JSON
        json_data = json.dumps(blockchain_data, indent=2)
        
        # Create response
        output = io.BytesIO()
        output.write(json_data.encode('utf-8'))
        output.seek(0)
        
        filename = f'simple_blockchain_export_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
        
        return send_file(
            output,
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"Error exporting blockchain: {str(e)}")
        return jsonify({'error': 'Failed to export blockchain data'}), 500

@admin_bp.route('/api/blockchain/status')
@admin_required
def api_blockchain_status():
    """
    API endpoint for real-time blockchain status
    """
    try:
        blockchain_manager = VehicleBlockchainManager()
        stats = blockchain_manager.verify_system_integrity()
        
        return jsonify({
            'blockchain_stats': stats,
            'last_updated': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting blockchain status: {str(e)}")
        return jsonify({
            'error': str(e),
            'blockchain_stats': {
                'blockchain_valid': False,
                'total_blocks': 0,
                'total_transactions': 0
            }
        }), 500