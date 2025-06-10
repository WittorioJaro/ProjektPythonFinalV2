from sqlalchemy import Column, Integer, String, Boolean, Text, ForeignKey, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, sessionmaker
from difflib import SequenceMatcher
from io import StringIO
import contextlib

Base = declarative_base()
class User(Base):
    """
    Represents a user in the system.
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    task_submissions = relationship("TaskSubmission", back_populates="user")


class Task(Base):
    """
    Represents a task that users can submit solutions for.
    """
    __tablename__ = 'tasks'

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    perfect_code = Column(Text, nullable=False)
    expected_output = Column(Text)
    rule_type = Column(String(20), nullable=False)
    max_score = Column(Integer, default=100)
    is_active = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey('users.id'))
    submissions = relationship("TaskSubmission", back_populates="task")


class TaskSubmission(Base):
    """
    Represents a user's submission for a specific task.
    """
    __tablename__ = 'task_submissions'

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey('tasks.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_content = Column(Text, nullable=False)

    score = Column(Integer)
    similarity_score = Column(Integer)
    output_match = Column(Boolean)

    submitted_at = Column(DateTime, default=func.current_timestamp())
    graded_at = Column(DateTime)

    task = relationship("Task", back_populates="submissions")
    user = relationship("User", back_populates="task_submissions")


class GradingRule(Base):
    """
    Defines the rules for assigning grades based on percentage scores.
    """
    __tablename__ = 'grading_rules'

    id = Column(Integer, primary_key=True)
    min_percentage = Column(Integer, nullable=False)
    max_percentage = Column(Integer, nullable=False)
    grade = Column(Integer, nullable=False)  #2-5

DATABASE_URL = 'sqlite:///users.db'
engine = create_engine(DATABASE_URL, echo=False)
Session = sessionmaker(bind=engine)
session = Session()

Base.metadata.create_all(engine)


def register_user(username: str, password: str, is_admin: bool = False) -> bool:
    """
    Registers a new user in the database.

    Args:
        username: The username for the new user.
        password: The password for the new user.
        is_admin: Flag indicating if the user is an administrator.

    Returns:
        True if registration is successful, False otherwise.
    """
    existing = session.query(User).filter_by(username=username).first()
    if existing:
        print(f"User '{username}' already exists.")
        return False

    new_user = User(username=username, password=password, is_admin=is_admin)
    session.add(new_user)
    session.commit()
    print(f"Registered '{username}'.")
    return True

def login_user(username: str, password: str):
    """
    Logs in an existing user.

    Args:
        username: The username of the user.
        password: The password of the user.

    Returns:
        The User object if login is successful, None otherwise.
    """
    user = session.query(User).filter_by(username=username).first()
    if not user:
        print("No such user.")
        return None
    if user.password != password:
        print("Błędne hasło.")
        return None
    print(f"Logged in '{username}' (is_admin={user.is_admin}).")
    return user

def add_task(title: str, description: str, perfect_code: str, expected_output: str, rule_type: str, max_score: int, created_by: int) -> bool:
    """
    Adds a new task to the database.

    Args:
        title: The title of the task.
        description: The description of the task.
        perfect_code: The reference solution code for the task.
        expected_output: The expected output of the perfect code.
        rule_type: The grading rule type ('code', 'output', 'both').
        max_score: The maximum score for the task.
        created_by: The ID of the user who created the task.

    Returns:
        True if the task is added successfully, False otherwise.
    """
    try:
        new_task = Task(
            title=title,
            description=description,
            perfect_code=perfect_code,
            expected_output=expected_output,
            rule_type=rule_type,
            max_score=max_score,
            created_by=created_by,
            is_active=True
        )
        session.add(new_task)
        session.commit()
        print(f"Task '{title}' added.")
        return True
    except Exception as e:
        session.rollback()
        print(f"Error while adding: {e}")
        return False

def get_tasks():
    """
    Retrieves all active tasks from the database.

    Returns:
        A list of active Task objects.
    """
    return session.query(Task).filter_by(is_active=True).all()

def submit_solution(task_id: int, user_id: int, file_name: str, file_content: str) -> bool:
    """
    Submits a solution for a task.

    Args:
        task_id: The ID of the task.
        user_id: The ID of the user submitting the solution.
        file_name: The name of the submitted file.
        file_content: The content of the submitted file.

    Returns:
        True if submission is successful, False otherwise.
    """
    try:
        submission = TaskSubmission(
            task_id=task_id,
            user_id=user_id,
            file_name=file_name,
            file_content=file_content
        )
        session.add(submission)
        session.commit()
        return True
    except Exception as e:
        print(f"Error submitting solution: {e}")
        session.rollback()
        return False

def get_task_submissions(task_id=None):
    """
    Retrieves task submissions.

    Args:
        task_id: Optional. The ID of the task to filter submissions by.
                 If None, retrieves all submissions.

    Returns:
        A list of TaskSubmission objects.
    """
    query = session.query(TaskSubmission).join(Task).join(User)
    if task_id is not None:
        query = query.filter(TaskSubmission.task_id == task_id)
    return query.all()

def get_task_by_id(task_id):
    """
    Retrieves a specific task by its ID.

    Args:
        task_id: The ID of the task.

    Returns:
        The Task object if found, None otherwise.
    """
    return session.query(Task).filter_by(id=task_id).first()

def get_all_tasks():
    """
    Retrieves all tasks from the database, regardless of active status.

    Returns:
        A list of all Task objects.
    """
    return session.query(Task).all()

def initialize_default_grading_rules():
    """
    Initializes default grading rules if no rules exist in the database.
    """
    default_rules = [
        {'min': 85, 'max': 100, 'grade': 5},
        {'min': 66, 'max': 84, 'grade': 4},
        {'min': 50, 'max': 65, 'grade': 3},
        {'min': 0, 'max': 49, 'grade': 2},
    ]

    existing_rules = session.query(GradingRule).count()
    if existing_rules == 0:
        for rule in default_rules:
            new_rule = GradingRule(
                min_percentage=rule['min'],
                max_percentage=rule['max'],
                grade=rule['grade']
            )
            session.add(new_rule)
        session.commit()

def update_grading_rule(rule_id: int, min_percentage: int, max_percentage: int, grade: int) -> bool:
    """
    Updates an existing grading rule.

    Args:
        rule_id: The ID of the grading rule to update.
        min_percentage: The new minimum percentage for the rule.
        max_percentage: The new maximum percentage for the rule.
        grade: The new grade associated with the rule.

    Returns:
        True if the update is successful, False otherwise.
    """
    try:
        rule = session.query(GradingRule).get(rule_id)
        if rule:
            rule.min_percentage = min_percentage
            rule.max_percentage = max_percentage
            rule.grade = grade
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        print(f"Error updating grading rule: {e}")
        return False

def get_grading_rules():
    """
    Retrieves all grading rules, ordered by minimum percentage descending.

    Returns:
        A list of GradingRule objects.
    """
    return session.query(GradingRule).order_by(GradingRule.min_percentage.desc()).all()

def get_grade_for_percentage(percentage: float) -> int:
    """
    Determines the grade for a given percentage based on the grading rules.

    Args:
        percentage: The percentage score.

    Returns:
        The corresponding grade (2-5). Defaults to 2 if no rule matches.
    """
    rule = session.query(GradingRule).filter(
        GradingRule.min_percentage <= percentage,
        GradingRule.max_percentage >= percentage
    ).first()
    return rule.grade if rule else 2

initialize_default_grading_rules()

def grade_submission(submission_id: int) -> bool:
    """
    Grades a specific task submission.

    Calculates code similarity and, if applicable, output similarity.
    Assigns a score and grade based on the task's rule type and grading rules.

    Args:
        submission_id: The ID of the submission to grade.

    Returns:
        True if grading is successful, False otherwise.
    """
    submission = session.query(TaskSubmission).get(submission_id)
    if not submission:
        return False

    task = submission.task

    def calculate_code_similarity(perfect_code: str, submitted_code: str) -> float:
        """Calculates the similarity ratio between two code strings."""
        return SequenceMatcher(None, perfect_code, submitted_code).ratio() * 100

    def calculate_output_similarity(expected_output: str, actual_output: str) -> float:
        """Calculates the similarity ratio between two output strings."""
        return SequenceMatcher(None, expected_output, actual_output).ratio() * 100

    def run_code_safely(code: str) -> str:
        """
        Executes Python code in a controlled environment and captures its stdout.

        Args:
            code: The Python code string to execute.

        Returns:
            The standard output of the executed code, or an error message.
        """
        output = StringIO()
        with contextlib.redirect_stdout(output):
            try:
                exec(code)
                return output.getvalue().strip()
            except Exception as e:
                return f"Error: {str(e)}"

    code_similarity = calculate_code_similarity(task.perfect_code.strip(), submission.file_content.strip())
    submission.similarity_score = int(code_similarity)

    if task.rule_type == 'code':
        final_percentage = code_similarity

    elif task.rule_type == 'output' or task.rule_type == 'both':
        actual_output = run_code_safely(submission.file_content)
        output_similarity = calculate_output_similarity(task.expected_output.strip(), actual_output.strip())
        submission.output_match = output_similarity >= 90

        if task.rule_type == 'output':
            final_percentage = output_similarity
        else:
            final_percentage = (code_similarity + output_similarity) / 2

    submission.score = get_grade_for_percentage(final_percentage)
    submission.graded_at = func.current_timestamp()
    session.commit()
    return True

def grade_all_submissions():
    """
    Grades all ungraded submissions in the database.

    Returns:
        True if all ungraded submissions are processed successfully, False otherwise.
    """
    try:
        ungraded_submissions = session.query(TaskSubmission).filter(TaskSubmission.graded_at.is_(None)).all()
        for submission in ungraded_submissions:
            grade_submission(submission.id)
        return True
    except Exception as e:
        print(f"Error grading submissions: {e}")
        return False
