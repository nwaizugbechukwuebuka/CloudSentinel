"""Task scheduling utilities for CloudSentinel."""

from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ScheduleType(Enum):
    """Schedule types for tasks."""
    ONCE = "once"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


@dataclass
class ScheduledTask:
    """Represents a scheduled task."""
    id: str
    name: str
    task_function: str
    schedule_type: ScheduleType
    schedule_config: Dict[str, Any]
    params: Dict[str, Any]
    is_active: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()


class TaskScheduler:
    """Advanced task scheduler for CloudSentinel operations."""
    
    def __init__(self):
        self.scheduled_tasks: Dict[str, ScheduledTask] = {}
        self.task_registry: Dict[str, Callable] = {}
        
    def register_task(self, name: str, task_function: Callable):
        """Register a task function."""
        self.task_registry[name] = task_function
        logger.info(f"Registered task function: {name}")
        
    def schedule_task(
        self,
        task_id: str,
        name: str,
        task_function: str,
        schedule_type: ScheduleType,
        schedule_config: Dict[str, Any],
        params: Optional[Dict[str, Any]] = None
    ) -> ScheduledTask:
        """Schedule a new task."""
        try:
            if task_function not in self.task_registry:
                raise ValueError(f"Task function '{task_function}' not registered")
            
            task = ScheduledTask(
                id=task_id,
                name=name,
                task_function=task_function,
                schedule_type=schedule_type,
                schedule_config=schedule_config,
                params=params or {}
            )
            
            # Calculate next run time
            task.next_run = self._calculate_next_run(task)
            
            self.scheduled_tasks[task_id] = task
            logger.info(f"Scheduled task '{name}' with ID '{task_id}'")
            
            return task
            
        except Exception as e:
            logger.error(f"Error scheduling task: {str(e)}")
            raise
    
    def schedule_scan_task(
        self,
        user_id: int,
        cloud_provider: str,
        schedule_config: Dict[str, Any],
        scan_params: Dict[str, Any]
    ) -> str:
        """Schedule a recurring security scan."""
        try:
            task_id = f"scan_{cloud_provider}_{user_id}_{datetime.utcnow().timestamp()}"
            
            # Determine schedule type from config
            if schedule_config.get("frequency") == "daily":
                schedule_type = ScheduleType.DAILY
            elif schedule_config.get("frequency") == "weekly":
                schedule_type = ScheduleType.WEEKLY
            elif schedule_config.get("frequency") == "monthly":
                schedule_type = ScheduleType.MONTHLY
            else:
                schedule_type = ScheduleType.CUSTOM
            
            params = {
                "user_id": user_id,
                "cloud_provider": cloud_provider,
                "scan_config": scan_params
            }
            
            task = self.schedule_task(
                task_id=task_id,
                name=f"Scheduled {cloud_provider.upper()} Scan",
                task_function="execute_scheduled_scan",
                schedule_type=schedule_type,
                schedule_config=schedule_config,
                params=params
            )
            
            logger.info(f"Scheduled {cloud_provider} scan for user {user_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Error scheduling scan task: {str(e)}")
            raise
    
    def schedule_cleanup_task(
        self,
        cleanup_type: str,
        retention_days: int,
        schedule_config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Schedule a cleanup task."""
        try:
            task_id = f"cleanup_{cleanup_type}_{datetime.utcnow().timestamp()}"
            
            default_schedule = {
                "frequency": "daily",
                "time": "02:00"  # 2 AM
            }
            
            schedule_config = schedule_config or default_schedule
            
            params = {
                "cleanup_type": cleanup_type,
                "retention_days": retention_days
            }
            
            task = self.schedule_task(
                task_id=task_id,
                name=f"Cleanup {cleanup_type}",
                task_function="execute_cleanup_task",
                schedule_type=ScheduleType.DAILY,
                schedule_config=schedule_config,
                params=params
            )
            
            logger.info(f"Scheduled cleanup task for {cleanup_type}")
            return task_id
            
        except Exception as e:
            logger.error(f"Error scheduling cleanup task: {str(e)}")
            raise
    
    def schedule_alert_task(
        self,
        alert_type: str,
        recipients: List[str],
        schedule_config: Dict[str, Any]
    ) -> str:
        """Schedule alert processing task."""
        try:
            task_id = f"alert_{alert_type}_{datetime.utcnow().timestamp()}"
            
            params = {
                "alert_type": alert_type,
                "recipients": recipients,
                "config": schedule_config
            }
            
            task = self.schedule_task(
                task_id=task_id,
                name=f"Alert Processing - {alert_type}",
                task_function="process_scheduled_alerts",
                schedule_type=ScheduleType.CUSTOM,
                schedule_config=schedule_config,
                params=params
            )
            
            logger.info(f"Scheduled alert task for {alert_type}")
            return task_id
            
        except Exception as e:
            logger.error(f"Error scheduling alert task: {str(e)}")
            raise
    
    def get_pending_tasks(self) -> List[ScheduledTask]:
        """Get tasks that are ready to run."""
        try:
            current_time = datetime.utcnow()
            pending_tasks = []
            
            for task in self.scheduled_tasks.values():
                if (task.is_active and 
                    task.next_run and 
                    task.next_run <= current_time):
                    pending_tasks.append(task)
            
            return pending_tasks
            
        except Exception as e:
            logger.error(f"Error getting pending tasks: {str(e)}")
            return []
    
    def execute_pending_tasks(self):
        """Execute all pending tasks."""
        try:
            pending_tasks = self.get_pending_tasks()
            
            for task in pending_tasks:
                try:
                    self._execute_task(task)
                except Exception as e:
                    logger.error(f"Error executing task {task.id}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error executing pending tasks: {str(e)}")
    
    def update_task_schedule(
        self,
        task_id: str,
        schedule_config: Dict[str, Any]
    ) -> bool:
        """Update task schedule configuration."""
        try:
            if task_id not in self.scheduled_tasks:
                return False
            
            task = self.scheduled_tasks[task_id]
            task.schedule_config = schedule_config
            task.next_run = self._calculate_next_run(task)
            
            logger.info(f"Updated schedule for task {task_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating task schedule: {str(e)}")
            return False
    
    def pause_task(self, task_id: str) -> bool:
        """Pause a scheduled task."""
        try:
            if task_id in self.scheduled_tasks:
                self.scheduled_tasks[task_id].is_active = False
                logger.info(f"Paused task {task_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error pausing task: {str(e)}")
            return False
    
    def resume_task(self, task_id: str) -> bool:
        """Resume a paused task."""
        try:
            if task_id in self.scheduled_tasks:
                task = self.scheduled_tasks[task_id]
                task.is_active = True
                task.next_run = self._calculate_next_run(task)
                logger.info(f"Resumed task {task_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error resuming task: {str(e)}")
            return False
    
    def delete_task(self, task_id: str) -> bool:
        """Delete a scheduled task."""
        try:
            if task_id in self.scheduled_tasks:
                del self.scheduled_tasks[task_id]
                logger.info(f"Deleted task {task_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error deleting task: {str(e)}")
            return False
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status information."""
        try:
            if task_id not in self.scheduled_tasks:
                return None
            
            task = self.scheduled_tasks[task_id]
            return {
                "id": task.id,
                "name": task.name,
                "is_active": task.is_active,
                "schedule_type": task.schedule_type.value,
                "last_run": task.last_run.isoformat() if task.last_run else None,
                "next_run": task.next_run.isoformat() if task.next_run else None,
                "created_at": task.created_at.isoformat(),
                "schedule_config": task.schedule_config
            }
            
        except Exception as e:
            logger.error(f"Error getting task status: {str(e)}")
            return None
    
    def list_tasks(self, active_only: bool = False) -> List[Dict[str, Any]]:
        """List all scheduled tasks."""
        try:
            tasks = []
            for task in self.scheduled_tasks.values():
                if active_only and not task.is_active:
                    continue
                    
                task_info = self.get_task_status(task.id)
                if task_info:
                    tasks.append(task_info)
            
            return tasks
            
        except Exception as e:
            logger.error(f"Error listing tasks: {str(e)}")
            return []
    
    def _execute_task(self, task: ScheduledTask):
        """Execute a single task."""
        try:
            logger.info(f"Executing task: {task.name} ({task.id})")
            
            # Get task function
            task_function = self.task_registry.get(task.task_function)
            if not task_function:
                raise ValueError(f"Task function '{task.task_function}' not found")
            
            # Execute task
            task_function(**task.params)
            
            # Update task timing
            task.last_run = datetime.utcnow()
            task.next_run = self._calculate_next_run(task)
            
            logger.info(f"Successfully executed task {task.id}")
            
        except Exception as e:
            logger.error(f"Error executing task {task.id}: {str(e)}")
            raise
    
    def _calculate_next_run(self, task: ScheduledTask) -> Optional[datetime]:
        """Calculate next run time for a task."""
        try:
            current_time = datetime.utcnow()
            schedule_config = task.schedule_config
            
            if task.schedule_type == ScheduleType.ONCE:
                # One-time task
                return schedule_config.get("run_at") or current_time
            
            elif task.schedule_type == ScheduleType.DAILY:
                # Daily task
                time_str = schedule_config.get("time", "00:00")
                hour, minute = map(int, time_str.split(":"))
                
                next_run = current_time.replace(hour=hour, minute=minute, second=0, microsecond=0)
                if next_run <= current_time:
                    next_run += timedelta(days=1)
                
                return next_run
            
            elif task.schedule_type == ScheduleType.WEEKLY:
                # Weekly task
                day_of_week = schedule_config.get("day_of_week", 0)  # 0 = Monday
                time_str = schedule_config.get("time", "00:00")
                hour, minute = map(int, time_str.split(":"))
                
                days_ahead = day_of_week - current_time.weekday()
                if days_ahead <= 0:  # Target day already happened this week
                    days_ahead += 7
                
                next_run = current_time + timedelta(days=days_ahead)
                next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
                
                return next_run
            
            elif task.schedule_type == ScheduleType.MONTHLY:
                # Monthly task
                day_of_month = schedule_config.get("day_of_month", 1)
                time_str = schedule_config.get("time", "00:00")
                hour, minute = map(int, time_str.split(":"))
                
                # Calculate next month
                if current_time.day < day_of_month:
                    next_run = current_time.replace(day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0)
                else:
                    # Next month
                    if current_time.month == 12:
                        next_run = current_time.replace(year=current_time.year + 1, month=1, day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0)
                    else:
                        next_run = current_time.replace(month=current_time.month + 1, day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0)
                
                return next_run
            
            elif task.schedule_type == ScheduleType.CUSTOM:
                # Custom interval
                interval_minutes = schedule_config.get("interval_minutes", 60)
                return current_time + timedelta(minutes=interval_minutes)
            
            else:
                logger.warning(f"Unknown schedule type: {task.schedule_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error calculating next run time: {str(e)}")
            return None
    
    def export_schedule(self) -> Dict[str, Any]:
        """Export current schedule configuration."""
        try:
            schedule_data = {
                "export_time": datetime.utcnow().isoformat(),
                "tasks": []
            }
            
            for task in self.scheduled_tasks.values():
                task_data = {
                    "id": task.id,
                    "name": task.name,
                    "task_function": task.task_function,
                    "schedule_type": task.schedule_type.value,
                    "schedule_config": task.schedule_config,
                    "params": task.params,
                    "is_active": task.is_active,
                    "created_at": task.created_at.isoformat()
                }
                schedule_data["tasks"].append(task_data)
            
            return schedule_data
            
        except Exception as e:
            logger.error(f"Error exporting schedule: {str(e)}")
            return {}
    
    def import_schedule(self, schedule_data: Dict[str, Any]) -> bool:
        """Import schedule configuration."""
        try:
            tasks_data = schedule_data.get("tasks", [])
            
            for task_data in tasks_data:
                task = ScheduledTask(
                    id=task_data["id"],
                    name=task_data["name"],
                    task_function=task_data["task_function"],
                    schedule_type=ScheduleType(task_data["schedule_type"]),
                    schedule_config=task_data["schedule_config"],
                    params=task_data["params"],
                    is_active=task_data["is_active"],
                    created_at=datetime.fromisoformat(task_data["created_at"])
                )
                
                task.next_run = self._calculate_next_run(task)
                self.scheduled_tasks[task.id] = task
            
            logger.info(f"Imported {len(tasks_data)} scheduled tasks")
            return True
            
        except Exception as e:
            logger.error(f"Error importing schedule: {str(e)}")
            return False


# Global scheduler instance
scheduler = TaskScheduler()
