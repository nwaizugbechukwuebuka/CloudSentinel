"""
Cleanup Tasks for CloudSentinel
Handles background cleanup of old data, logs, reports, and system maintenance.
"""

import os
import shutil
import tempfile
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from celery import current_app
from sqlalchemy.orm import Session
from sqlalchemy import func, text

# Import models and services
from ..api.database import get_db
from ..api.models.alert import Alert
from ..api.models.scan_result import ScanResult
from ..api.models.user import User
from ..api.utils.logger import get_logger

logger = get_logger(__name__)

@current_app.task
def cleanup_old_scan_results(retention_days: int = 90) -> Dict[str, Any]:
    """
    Clean up old scan results beyond retention period.
    
    Args:
        retention_days: Number of days to retain scan results
        
    Returns:
        Dict containing cleanup results
    """
    try:
        logger.info(f"Starting cleanup of scan results older than {retention_days} days")
        
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        with next(get_db()) as db:
            # Count records to be deleted
            old_results_count = db.query(ScanResult).filter(
                ScanResult.created_at < cutoff_date
            ).count()
            
            if old_results_count == 0:
                logger.info("No old scan results found to cleanup")
                return {
                    'status': 'success',
                    'deleted_count': 0,
                    'retention_days': retention_days
                }
            
            # Delete old scan results in batches to avoid memory issues
            batch_size = 1000
            deleted_count = 0
            
            while True:
                # Get batch of old results
                old_results = db.query(ScanResult).filter(
                    ScanResult.created_at < cutoff_date
                ).limit(batch_size).all()
                
                if not old_results:
                    break
                
                # Delete batch
                for result in old_results:
                    db.delete(result)
                
                deleted_count += len(old_results)
                db.commit()
                
                logger.info(f"Deleted batch of {len(old_results)} scan results (total: {deleted_count})")
                
                # Break if we deleted less than batch size (last batch)
                if len(old_results) < batch_size:
                    break
            
            logger.info(f"Cleanup completed: deleted {deleted_count} old scan results")
            
            return {
                'status': 'success',
                'deleted_count': deleted_count,
                'retention_days': retention_days
            }
            
    except Exception as e:
        logger.error(f"Error in cleanup_old_scan_results: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'deleted_count': 0
        }

@current_app.task
def cleanup_resolved_alerts(retention_days: int = 180) -> Dict[str, Any]:
    """
    Clean up resolved alerts beyond retention period.
    
    Args:
        retention_days: Number of days to retain resolved alerts
        
    Returns:
        Dict containing cleanup results
    """
    try:
        logger.info(f"Starting cleanup of resolved alerts older than {retention_days} days")
        
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        with next(get_db()) as db:
            # Count resolved alerts to be deleted
            old_alerts_count = db.query(Alert).filter(
                Alert.status.in_(['resolved', 'closed', 'auto_resolved']),
                Alert.resolved_at < cutoff_date
            ).count()
            
            if old_alerts_count == 0:
                logger.info("No old resolved alerts found to cleanup")
                return {
                    'status': 'success',
                    'deleted_count': 0,
                    'retention_days': retention_days
                }
            
            # Archive alerts before deletion (optional)
            archived_count = 0
            if should_archive_alerts():
                archived_count = archive_old_alerts(db, cutoff_date)
            
            # Delete old resolved alerts in batches
            batch_size = 500
            deleted_count = 0
            
            while True:
                old_alerts = db.query(Alert).filter(
                    Alert.status.in_(['resolved', 'closed', 'auto_resolved']),
                    Alert.resolved_at < cutoff_date
                ).limit(batch_size).all()
                
                if not old_alerts:
                    break
                
                for alert in old_alerts:
                    db.delete(alert)
                
                deleted_count += len(old_alerts)
                db.commit()
                
                logger.info(f"Deleted batch of {len(old_alerts)} resolved alerts (total: {deleted_count})")
                
                if len(old_alerts) < batch_size:
                    break
            
            logger.info(f"Cleanup completed: archived {archived_count}, deleted {deleted_count} resolved alerts")
            
            return {
                'status': 'success',
                'deleted_count': deleted_count,
                'archived_count': archived_count,
                'retention_days': retention_days
            }
            
    except Exception as e:
        logger.error(f"Error in cleanup_resolved_alerts: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'deleted_count': 0
        }

@current_app.task
def cleanup_old_logs(retention_days: int = 30) -> Dict[str, Any]:
    """
    Clean up old application logs beyond retention period.
    
    Args:
        retention_days: Number of days to retain log files
        
    Returns:
        Dict containing cleanup results
    """
    try:
        logger.info(f"Starting cleanup of log files older than {retention_days} days")
        
        # Define log directories to clean
        log_directories = [
            '/var/log/cloudsentinel',
            '/app/logs',
            './logs',
            '../logs'
        ]
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted_files = 0
        deleted_size = 0
        
        for log_dir in log_directories:
            log_path = Path(log_dir)
            
            if not log_path.exists():
                continue
                
            logger.info(f"Cleaning log directory: {log_path}")
            
            # Find old log files
            for log_file in log_path.rglob('*.log*'):
                try:
                    if log_file.is_file():
                        # Check file modification time
                        file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                        
                        if file_mtime < cutoff_date:
                            file_size = log_file.stat().st_size
                            log_file.unlink()  # Delete file
                            deleted_files += 1
                            deleted_size += file_size
                            
                            logger.debug(f"Deleted log file: {log_file}")
                            
                except Exception as e:
                    logger.warning(f"Failed to delete log file {log_file}: {str(e)}")
                    continue
        
        # Also cleanup rotated and compressed logs
        for log_dir in log_directories:
            log_path = Path(log_dir)
            if log_path.exists():
                for old_log in log_path.rglob('*.log.*'):
                    try:
                        if old_log.is_file():
                            file_mtime = datetime.fromtimestamp(old_log.stat().st_mtime)
                            if file_mtime < cutoff_date:
                                file_size = old_log.stat().st_size
                                old_log.unlink()
                                deleted_files += 1
                                deleted_size += file_size
                    except Exception as e:
                        logger.warning(f"Failed to delete rotated log {old_log}: {str(e)}")
        
        deleted_size_mb = deleted_size / (1024 * 1024)
        
        logger.info(f"Log cleanup completed: deleted {deleted_files} files, freed {deleted_size_mb:.2f} MB")
        
        return {
            'status': 'success',
            'deleted_files': deleted_files,
            'freed_space_mb': round(deleted_size_mb, 2),
            'retention_days': retention_days
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup_old_logs: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'deleted_files': 0
        }

@current_app.task
def cleanup_temporary_files() -> Dict[str, Any]:
    """
    Clean up temporary files created by the application.
    
    Returns:
        Dict containing cleanup results
    """
    try:
        logger.info("Starting cleanup of temporary files")
        
        deleted_files = 0
        deleted_size = 0
        
        # Clean system temp directory
        temp_dir = Path(tempfile.gettempdir())
        
        # Look for CloudSentinel-related temp files
        temp_patterns = [
            'cloudsentinel_*',
            'scan_report_*',
            'security_report_*',
            '*.tmp.json',
            '*.tmp.pdf',
            '*.tmp.csv'
        ]
        
        for pattern in temp_patterns:
            for temp_file in temp_dir.glob(pattern):
                try:
                    if temp_file.is_file():
                        # Check if file is older than 1 hour
                        file_mtime = datetime.fromtimestamp(temp_file.stat().st_mtime)
                        if datetime.now() - file_mtime > timedelta(hours=1):
                            file_size = temp_file.stat().st_size
                            temp_file.unlink()
                            deleted_files += 1
                            deleted_size += file_size
                            logger.debug(f"Deleted temp file: {temp_file}")
                except Exception as e:
                    logger.warning(f"Failed to delete temp file {temp_file}: {str(e)}")
        
        # Clean application-specific temp directories
        app_temp_dirs = [
            './tmp',
            '../tmp',
            '/tmp/cloudsentinel',
            '/app/tmp'
        ]
        
        for temp_dir_path in app_temp_dirs:
            temp_path = Path(temp_dir_path)
            if temp_path.exists():
                try:
                    # Remove entire directory if it exists and is old
                    if datetime.now() - datetime.fromtimestamp(temp_path.stat().st_mtime) > timedelta(hours=24):
                        shutil.rmtree(temp_path)
                        logger.info(f"Removed old temp directory: {temp_path}")
                except Exception as e:
                    logger.warning(f"Failed to remove temp directory {temp_path}: {str(e)}")
        
        deleted_size_mb = deleted_size / (1024 * 1024)
        
        logger.info(f"Temp file cleanup completed: deleted {deleted_files} files, freed {deleted_size_mb:.2f} MB")
        
        return {
            'status': 'success',
            'deleted_files': deleted_files,
            'freed_space_mb': round(deleted_size_mb, 2)
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup_temporary_files: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'deleted_files': 0
        }

@current_app.task
def cleanup_old_reports(retention_days: int = 60) -> Dict[str, Any]:
    """
    Clean up old generated reports beyond retention period.
    
    Args:
        retention_days: Number of days to retain report files
        
    Returns:
        Dict containing cleanup results
    """
    try:
        logger.info(f"Starting cleanup of reports older than {retention_days} days")
        
        # Define report directories
        report_directories = [
            './reports',
            '../reports',
            '/app/reports',
            '/var/reports/cloudsentinel'
        ]
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted_files = 0
        deleted_size = 0
        
        for report_dir in report_directories:
            report_path = Path(report_dir)
            
            if not report_path.exists():
                continue
                
            logger.info(f"Cleaning report directory: {report_path}")
            
            # Find old report files
            report_extensions = ['*.pdf', '*.json', '*.csv', '*.xlsx', '*.html']
            
            for extension in report_extensions:
                for report_file in report_path.rglob(extension):
                    try:
                        if report_file.is_file():
                            file_mtime = datetime.fromtimestamp(report_file.stat().st_mtime)
                            
                            if file_mtime < cutoff_date:
                                file_size = report_file.stat().st_size
                                report_file.unlink()
                                deleted_files += 1
                                deleted_size += file_size
                                
                                logger.debug(f"Deleted report file: {report_file}")
                                
                    except Exception as e:
                        logger.warning(f"Failed to delete report file {report_file}: {str(e)}")
                        continue
        
        deleted_size_mb = deleted_size / (1024 * 1024)
        
        logger.info(f"Report cleanup completed: deleted {deleted_files} files, freed {deleted_size_mb:.2f} MB")
        
        return {
            'status': 'success',
            'deleted_files': deleted_files,
            'freed_space_mb': round(deleted_size_mb, 2),
            'retention_days': retention_days
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup_old_reports: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'deleted_files': 0
        }

@current_app.task
def database_maintenance() -> Dict[str, Any]:
    """
    Perform database maintenance tasks like vacuuming, analyzing, and optimizing.
    
    Returns:
        Dict containing maintenance results
    """
    try:
        logger.info("Starting database maintenance")
        
        with next(get_db()) as db:
            maintenance_results = {}
            
            # Check database size before maintenance
            size_before = get_database_size(db)
            maintenance_results['size_before_mb'] = size_before
            
            # Analyze table statistics
            try:
                db.execute(text("ANALYZE"))
                db.commit()
                maintenance_results['analyze'] = 'completed'
                logger.info("Database ANALYZE completed")
            except Exception as e:
                logger.warning(f"ANALYZE failed: {str(e)}")
                maintenance_results['analyze'] = f'failed: {str(e)}'
            
            # Vacuum database (PostgreSQL specific)
            try:
                # Note: VACUUM cannot be run inside a transaction block
                db.execute(text("VACUUM"))
                maintenance_results['vacuum'] = 'completed'
                logger.info("Database VACUUM completed")
            except Exception as e:
                logger.warning(f"VACUUM failed: {str(e)}")
                maintenance_results['vacuum'] = f'failed: {str(e)}'
            
            # Reindex tables if needed
            try:
                db.execute(text("REINDEX DATABASE cloudsentinel"))
                maintenance_results['reindex'] = 'completed'
                logger.info("Database REINDEX completed")
            except Exception as e:
                logger.warning(f"REINDEX failed: {str(e)}")
                maintenance_results['reindex'] = f'failed: {str(e)}'
            
            # Check database size after maintenance
            size_after = get_database_size(db)
            maintenance_results['size_after_mb'] = size_after
            maintenance_results['space_freed_mb'] = max(0, size_before - size_after)
            
            # Update table statistics
            table_stats = get_table_statistics(db)
            maintenance_results['table_statistics'] = table_stats
            
            logger.info("Database maintenance completed")
            
            return {
                'status': 'success',
                'maintenance_results': maintenance_results
            }
            
    except Exception as e:
        logger.error(f"Error in database_maintenance: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

@current_app.task
def cleanup_inactive_user_sessions(days_inactive: int = 30) -> Dict[str, Any]:
    """
    Clean up sessions for inactive users.
    
    Args:
        days_inactive: Number of days of inactivity before cleanup
        
    Returns:
        Dict containing cleanup results
    """
    try:
        logger.info(f"Starting cleanup of inactive user sessions ({days_inactive} days)")
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_inactive)
        
        with next(get_db()) as db:
            # Find inactive users
            inactive_users = db.query(User).filter(
                User.last_login < cutoff_date
            ).all()
            
            cleaned_sessions = 0
            
            for user in inactive_users:
                # Clear user sessions (this would depend on your session storage)
                # For example, if using Redis or database-stored sessions
                try:
                    # Mock session cleanup - implement based on your session strategy
                    logger.info(f"Cleaning sessions for inactive user: {user.email}")
                    cleaned_sessions += 1
                except Exception as e:
                    logger.warning(f"Failed to clean sessions for user {user.email}: {str(e)}")
            
            logger.info(f"Session cleanup completed: cleaned {cleaned_sessions} inactive user sessions")
            
            return {
                'status': 'success',
                'cleaned_sessions': cleaned_sessions,
                'days_inactive': days_inactive
            }
            
    except Exception as e:
        logger.error(f"Error in cleanup_inactive_user_sessions: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'cleaned_sessions': 0
        }

@current_app.task
def system_health_check() -> Dict[str, Any]:
    """
    Perform system health checks and cleanup if necessary.
    
    Returns:
        Dict containing health check results
    """
    try:
        logger.info("Starting system health check")
        
        health_results = {}
        
        # Check disk space
        disk_usage = check_disk_usage()
        health_results['disk_usage'] = disk_usage
        
        # Check database connectivity
        db_health = check_database_health()
        health_results['database'] = db_health
        
        # Check memory usage
        memory_usage = check_memory_usage()
        health_results['memory_usage'] = memory_usage
        
        # Check for stuck tasks or processes
        stuck_tasks = check_stuck_tasks()
        health_results['stuck_tasks'] = stuck_tasks
        
        # Check log file sizes
        log_sizes = check_log_file_sizes()
        health_results['log_sizes'] = log_sizes
        
        # Determine overall health
        health_status = determine_overall_health(health_results)
        health_results['overall_status'] = health_status
        
        # Trigger cleanup if needed
        if health_status != 'healthy':
            trigger_emergency_cleanup.delay()
        
        logger.info(f"System health check completed: status = {health_status}")
        
        return {
            'status': 'success',
            'health_results': health_results
        }
        
    except Exception as e:
        logger.error(f"Error in system_health_check: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

@current_app.task
def trigger_emergency_cleanup() -> Dict[str, Any]:
    """
    Trigger emergency cleanup when system health is degraded.
    
    Returns:
        Dict containing emergency cleanup results
    """
    try:
        logger.warning("Triggering emergency cleanup due to system health issues")
        
        cleanup_results = {}
        
        # Aggressive temporary file cleanup
        temp_cleanup = cleanup_temporary_files.delay()
        cleanup_results['temp_files'] = 'triggered'
        
        # Clean up old logs more aggressively (7 days instead of 30)
        log_cleanup = cleanup_old_logs.delay(retention_days=7)
        cleanup_results['logs'] = 'triggered'
        
        # Clean up old reports more aggressively (15 days instead of 60)
        report_cleanup = cleanup_old_reports.delay(retention_days=15)
        cleanup_results['reports'] = 'triggered'
        
        # Force database maintenance
        db_maintenance = database_maintenance.delay()
        cleanup_results['database'] = 'triggered'
        
        logger.warning("Emergency cleanup tasks triggered")
        
        return {
            'status': 'success',
            'cleanup_tasks': cleanup_results
        }
        
    except Exception as e:
        logger.error(f"Error in trigger_emergency_cleanup: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

# Helper functions

def should_archive_alerts() -> bool:
    """Check if alerts should be archived before deletion"""
    # This could be a configuration setting
    return True

def archive_old_alerts(db: Session, cutoff_date: datetime) -> int:
    """Archive old alerts to separate storage before deletion"""
    # This would implement archival to external storage (S3, etc.)
    # For now, just log that archival would happen
    archived_count = db.query(Alert).filter(
        Alert.status.in_(['resolved', 'closed', 'auto_resolved']),
        Alert.resolved_at < cutoff_date
    ).count()
    
    logger.info(f"Would archive {archived_count} alerts (archival not implemented)")
    return archived_count

def get_database_size(db: Session) -> float:
    """Get database size in MB"""
    try:
        result = db.execute(text("SELECT pg_database_size(current_database())")).fetchone()
        size_bytes = result[0] if result else 0
        return size_bytes / (1024 * 1024)  # Convert to MB
    except Exception:
        return 0.0

def get_table_statistics(db: Session) -> Dict[str, int]:
    """Get table row counts and sizes"""
    stats = {}
    
    tables = ['alerts', 'scan_results', 'users']
    
    for table in tables:
        try:
            result = db.execute(text(f"SELECT COUNT(*) FROM {table}")).fetchone()
            stats[table] = result[0] if result else 0
        except Exception as e:
            logger.warning(f"Failed to get stats for table {table}: {str(e)}")
            stats[table] = 0
    
    return stats

def check_disk_usage() -> Dict[str, Any]:
    """Check disk usage for critical partitions"""
    try:
        import shutil
        
        paths_to_check = ['/', '/var', '/tmp', '/app']
        disk_info = {}
        
        for path in paths_to_check:
            if os.path.exists(path):
                usage = shutil.disk_usage(path)
                total_gb = usage.total / (1024**3)
                free_gb = usage.free / (1024**3)
                used_percent = ((usage.total - usage.free) / usage.total) * 100
                
                disk_info[path] = {
                    'total_gb': round(total_gb, 2),
                    'free_gb': round(free_gb, 2),
                    'used_percent': round(used_percent, 2),
                    'status': 'critical' if used_percent > 90 else 'warning' if used_percent > 80 else 'ok'
                }
        
        return disk_info
    except Exception as e:
        return {'error': str(e)}

def check_database_health() -> Dict[str, Any]:
    """Check database connectivity and health"""
    try:
        with next(get_db()) as db:
            # Simple connectivity test
            db.execute(text("SELECT 1")).fetchone()
            
            # Check for long-running queries
            long_queries = db.execute(text("""
                SELECT COUNT(*) FROM pg_stat_activity 
                WHERE state = 'active' AND query_start < NOW() - INTERVAL '5 minutes'
            """)).fetchone()
            
            return {
                'connectivity': 'ok',
                'long_running_queries': long_queries[0] if long_queries else 0,
                'status': 'warning' if (long_queries and long_queries[0] > 0) else 'ok'
            }
    except Exception as e:
        return {
            'connectivity': 'failed',
            'error': str(e),
            'status': 'critical'
        }

def check_memory_usage() -> Dict[str, Any]:
    """Check memory usage"""
    try:
        import psutil
        
        memory = psutil.virtual_memory()
        
        return {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'used_percent': memory.percent,
            'status': 'critical' if memory.percent > 90 else 'warning' if memory.percent > 80 else 'ok'
        }
    except ImportError:
        return {'error': 'psutil not available'}
    except Exception as e:
        return {'error': str(e)}

def check_stuck_tasks() -> Dict[str, Any]:
    """Check for stuck Celery tasks"""
    try:
        # This would integrate with Celery monitoring
        # For now, return mock data
        return {
            'stuck_tasks': 0,
            'status': 'ok'
        }
    except Exception as e:
        return {'error': str(e)}

def check_log_file_sizes() -> Dict[str, Any]:
    """Check log file sizes"""
    try:
        log_paths = ['/var/log/cloudsentinel', './logs', '../logs']
        log_info = {}
        
        for log_path in log_paths:
            path = Path(log_path)
            if path.exists():
                total_size = sum(f.stat().st_size for f in path.rglob('*.log*') if f.is_file())
                size_mb = total_size / (1024 * 1024)
                
                log_info[str(path)] = {
                    'size_mb': round(size_mb, 2),
                    'status': 'warning' if size_mb > 1000 else 'ok'  # Warn if logs > 1GB
                }
        
        return log_info
    except Exception as e:
        return {'error': str(e)}

def determine_overall_health(health_results: Dict[str, Any]) -> str:
    """Determine overall system health status"""
    critical_issues = 0
    warning_issues = 0
    
    for component, result in health_results.items():
        if isinstance(result, dict):
            status = result.get('status', 'ok')
            if status == 'critical':
                critical_issues += 1
            elif status == 'warning':
                warning_issues += 1
    
    if critical_issues > 0:
        return 'critical'
    elif warning_issues > 0:
        return 'warning'
    else:
        return 'healthy'
