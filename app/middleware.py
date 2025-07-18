# app/middleware.py
from flask import request, g, session
from datetime import datetime
from app import db
from app.models.request_log import RequestLog
# Removed AnomalyDetection import since the method doesn't exist
import time
import logging
from datetime import timedelta

logger = logging.getLogger(__name__)

def setup_request_middleware(app):
    """
    Sets up middleware for request logging and anomaly detection
    """
    @app.before_request
    def before_request():
        # Store request start time for performance tracking
        g.start_time = time.time()
        
        # Skip static file requests
        if request.path.startswith('/static'):
            return
        
        # Store request data
        g.request_data = {
            'endpoint': request.endpoint,
            'path': request.path,
            'method': request.method,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string if request.user_agent else None,
            'user_id': None,  # Will be set later if user authenticates
        }
        
    @app.after_request
    def after_request(response):
        # Skip static file requests
        if request.path.startswith('/static'):
            return response
        
        try:
            # Calculate response time
            response_time_ms = None
            if hasattr(g, 'start_time'):
                response_time_ms = int((time.time() - g.start_time) * 1000)
            
            # Get user_id if available
            user_id = None
            if hasattr(g, 'request_data'):
                user_id = g.request_data.get('user_id')
            elif 'user_id' in session:
                user_id = session['user_id']
            
            # Simplified anomaly detection
            has_anomaly = False
            anomaly_details = None
            
            # Check for suspicious endpoints with slow responses
            suspicious_endpoints = ['/admin', '/api', '/login', '/register']
            if any(endpoint in request.path for endpoint in suspicious_endpoints):
                # Check if too many requests to sensitive endpoints
                if response_time_ms and response_time_ms > 5000:  # Very slow response
                    has_anomaly = True
                    anomaly_details = f"Slow response to sensitive endpoint: {response_time_ms}ms"
            
            # Check for failed requests
            if response.status_code >= 400:
                # Count recent failed requests from this IP
                try:
                    recent_failures = RequestLog.query.filter(
                        RequestLog.ip_address == request.remote_addr,
                        RequestLog.status_code >= 400,
                        RequestLog.created_at >= datetime.utcnow() - timedelta(minutes=5)
                    ).count()
                    
                    if recent_failures >= 3:  # 3 or more failures in 5 minutes
                        has_anomaly = True
                        anomaly_details = f"Multiple failed requests: {recent_failures + 1} failures in 5 minutes"
                except Exception as e:
                    logger.warning(f"Could not check recent failures: {str(e)}")
            
            # Check for unusual user agents
            if request.user_agent:
                suspicious_agents = ['curl', 'wget', 'python', 'bot', 'crawler', 'spider']
                user_agent_lower = request.user_agent.string.lower()
                if any(agent in user_agent_lower for agent in suspicious_agents):
                    has_anomaly = True
                    anomaly_details = f"Suspicious user agent: {request.user_agent.string[:100]}"
            
            # Check for rapid requests (simple rate limiting check)
            if request.remote_addr:
                try:
                    # Count requests from this IP in last minute
                    recent_requests = RequestLog.query.filter(
                        RequestLog.ip_address == request.remote_addr,
                        RequestLog.created_at >= datetime.utcnow() - timedelta(minutes=1)
                    ).count()
                    
                    if recent_requests >= 20:  # More than 20 requests per minute
                        has_anomaly = True
                        anomaly_details = f"High request rate: {recent_requests + 1} requests in 1 minute"
                except Exception as e:
                    logger.warning(f"Could not check request rate: {str(e)}")
            
            # Log the request with proper response time
            log_entry = RequestLog(
                user_id=user_id,
                endpoint=request.endpoint or request.path,
                method=request.method,
                status_code=response.status_code,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string if request.user_agent else None,
                response_time_ms=response_time_ms,
                has_anomaly=has_anomaly,
                anomaly_details=anomaly_details
            )
            
            db.session.add(log_entry)
            db.session.commit()
            
        except Exception as e:
            # Log error but don't affect the response
            logger.error(f"Error in request logging middleware: {str(e)}")
            try:
                db.session.rollback()
            except:
                pass  # In case rollback also fails
        
        return response
    
    # Set up session management
    @app.before_request
    def update_user_session():
        # Skip static file requests
        if request.path.startswith('/static'):
            return
            
        try:
            # If user is authenticated, update last activity timestamp
            if 'user_id' in session:
                session['last_activity'] = datetime.utcnow().timestamp()
                
                # If we're tracking request information, add user_id
                if hasattr(g, 'request_data'):
                    g.request_data['user_id'] = session['user_id']
        except Exception as e:
            # Log error but don't affect the request
            logger.error(f"Error in session management middleware: {str(e)}")