import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from database import (register_user, login_user, add_task, get_tasks, submit_solution,
                          get_task_submissions, get_all_tasks, get_grading_rules,
                          update_grading_rule, grade_submission, grade_all_submissions)

def show_main_view(user):
    """
    Displays the main application view after a successful login.

    Clears the existing widgets and sets up a notebook interface with different
    tabs based on whether the user is an admin or a regular user.

    Args:
        user: The logged-in user object, containing user details and admin status.
    """
    for widget in root.winfo_children():
        widget.destroy()
    notebook = ttk.Notebook(root)

    tasks_frame = tk.Frame(notebook)
    notebook.add(tasks_frame, text="Tasks")

    if user.is_admin:
        task_select_frame = ttk.Frame(tasks_frame)
        task_select_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(task_select_frame, text="Select Task:").pack(side="left", padx=5)
        task_var = tk.StringVar()
        tasks = get_all_tasks()
        task_choices = {f"{task.title} (ID: {task.id})": task.id for task in tasks}
        task_dropdown = ttk.Combobox(task_select_frame, textvariable=task_var, values=list(task_choices.keys()), state="readonly")
        task_dropdown.pack(side="left", padx=5, fill="x", expand=True)

        submissions_frame = ttk.Frame(tasks_frame)
        submissions_frame.pack(fill="both", expand=True, padx=10, pady=5)

        canvas = tk.Canvas(submissions_frame)
        scrollbar = ttk.Scrollbar(submissions_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def show_submissions(*args):
            """
            Displays submissions for the selected task in the admin view.

            Clears previous submissions and populates the scrollable frame
            with details of each submission for the chosen task.

            Args:
                *args: Variable length argument list (used by trace).
            """
            for widget in scrollable_frame.winfo_children():
                widget.destroy()

            if not task_var.get():
                return

            task_id = task_choices[task_var.get()]
            submissions = get_task_submissions(task_id)

            if not submissions:
                ttk.Label(scrollable_frame, text="No submissions for this task yet.").pack(pady=10)
                return

            for submission in submissions:
                sub_frame = ttk.LabelFrame(scrollable_frame, text=f"Submission by {submission.user.username}")
                sub_frame.pack(fill="x", padx=5, pady=5, expand=True)

                ttk.Label(sub_frame, text=f"File: {submission.file_name}").pack(anchor="w", padx=5)
                ttk.Label(sub_frame, text=f"Submitted: {submission.submitted_at}").pack(anchor="w", padx=5)

                code_text = tk.Text(sub_frame, height=10, width=60, wrap=tk.NONE)
                code_text.insert("1.0", submission.file_content)
                code_text.config(state=tk.DISABLED)
                code_text.pack(padx=5, pady=5, fill="both", expand=True)

                status_frame = ttk.Frame(sub_frame)
                status_frame.pack(fill="x", padx=5, pady=5)

                if submission.score is not None:
                    ttk.Label(status_frame, text=f"Score: {submission.score}").pack(side="left", padx=5)
                if submission.similarity_score is not None:
                    ttk.Label(status_frame, text=f"Similarity: {submission.similarity_score}%").pack(side="left", padx=5)
                if submission.output_match is not None:
                    ttk.Label(status_frame, text=f"Output Match: {'Yes' if submission.output_match else 'No'}").pack(side="left", padx=5)

        task_var.trace('w', show_submissions)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        grading_rules_frame = tk.Frame(notebook)
        notebook.add(grading_rules_frame, text="Grading Rules")

        rules_list_frame = ttk.Frame(grading_rules_frame)
        rules_list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Label(rules_list_frame, text="Grade").grid(row=0, column=0, padx=5, pady=5)
        ttk.Label(rules_list_frame, text="Min %").grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(rules_list_frame, text="Max %").grid(row=0, column=2, padx=5, pady=5)
        ttk.Label(rules_list_frame, text="Actions").grid(row=0, column=3, padx=5, pady=5)

        def save_rule_changes(rule_id, min_var, max_var, grade_var):
            """
            Saves changes made to a specific grading rule.

            Validates the input values and calls the database function to update
            the rule. Shows success or error messages accordingly.

            Args:
                rule_id: The ID of the grading rule to update.
                min_var: tkinter.StringVar holding the minimum percentage.
                max_var: tkinter.StringVar holding the maximum percentage.
                grade_var: tkinter.StringVar holding the grade.
            """
            try:
                min_val = int(min_var.get())
                max_val = int(max_var.get())
                grade_val = int(grade_var.get())

                if min_val < 0 or max_val > 100 or min_val >= max_val or grade_val < 2 or grade_val > 5:
                    messagebox.showerror("Error", "Invalid values. Please check your inputs.")
                    return

                if update_grading_rule(rule_id, min_val, max_val, grade_val):
                    messagebox.showinfo("Success", "Grading rule updated successfully!")
                    refresh_rules()
                else:
                    messagebox.showerror("Error", "Failed to update grading rule.")
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numbers.")

        def refresh_rules():
            """
            Refreshes the display of grading rules in the admin panel.

            Clears the existing rules and repopulates the list with current
            grading rules from the database.
            """
            for widget in rules_list_frame.grid_slaves():
                if int(widget.grid_info()["row"]) > 0:
                    widget.destroy()

            for idx, rule in enumerate(get_grading_rules(), 1):
                grade_var = tk.StringVar(value=str(rule.grade))
                min_var = tk.StringVar(value=str(rule.min_percentage))
                max_var = tk.StringVar(value=str(rule.max_percentage))

                ttk.Entry(rules_list_frame, textvariable=grade_var, width=10).grid(row=idx, column=0, padx=5, pady=2)
                ttk.Entry(rules_list_frame, textvariable=min_var, width=10).grid(row=idx, column=1, padx=5, pady=2)
                ttk.Entry(rules_list_frame, textvariable=max_var, width=10).grid(row=idx, column=2, padx=5, pady=2)

                save_btn = ttk.Button(
                    rules_list_frame,
                    text="Save",
                    command=lambda r=rule.id, min_v=min_var, max_v=max_var, g_v=grade_var:
                        save_rule_changes(r, min_v, max_v, g_v)
                )
                save_btn.grid(row=idx, column=3, padx=5, pady=2)

        refresh_rules()

        def grade_selected_task():
            """
            Initiates grading for all submissions of the currently selected task.

            Shows a warning if no task is selected. Otherwise, iterates through
            submissions of the selected task and grades them.
            """
            if not task_var.get():
                messagebox.showwarning("Warning", "Please select a task first.")
                return
            task_id = task_choices[task_var.get()]
            submissions = get_task_submissions(task_id)
            for submission in submissions:
                if grade_submission(submission.id):
                    show_submissions()
            messagebox.showinfo("Success", "Selected task has been graded!")

        def grade_all_tasks():
            """
            Initiates grading for all ungraded submissions across all tasks.

            Calls the database function to grade all submissions and shows
            a success or error message.
            """
            if grade_all_submissions():
                show_submissions()
                messagebox.showinfo("Success", "All tasks have been graded!")
            else:
                messagebox.showerror("Error", "Failed to grade all tasks.")

        grade_buttons_frame = ttk.Frame(task_select_frame)
        grade_buttons_frame.pack(side="right", padx=5)

        ttk.Button(grade_buttons_frame, text="Grade Selected Task", command=grade_selected_task).pack(side="left", padx=5)
        ttk.Button(grade_buttons_frame, text="Grade All Tasks", command=grade_all_tasks).pack(side="left", padx=5)

    else:
        canvas = tk.Canvas(tasks_frame)
        scrollbar = ttk.Scrollbar(tasks_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        tasks = get_tasks()

        def handle_file_upload(task_id):
            """
            Handles the process of a user uploading a solution file for a task.

            Opens a file dialog for the user to select a Python file. Reads the
            file content and submits it as a solution for the specified task.

            Args:
                task_id: The ID of the task for which the solution is being submitted.
            """
            file_path = filedialog.askopenfilename(
                title="Select Python File",
                filetypes=[("Python files", "*.py")]
            )
            if file_path:
                try:
                    with open(file_path, 'r') as file:
                        content = file.read()
                        file_name = file_path.split('/')[-1]
                        if submit_solution(task_id, user.id, file_name, content):
                            messagebox.showinfo("Success", "Solution submitted successfully!")
                        else:
                            messagebox.showerror("Error", "Failed to submit solution")
                except Exception as e:
                    messagebox.showerror("Error", f"Error reading file: {str(e)}")

        for i, task in enumerate(tasks):
            task_frame = ttk.LabelFrame(scrollable_frame, text=f"Task: {task.title}")
            task_frame.pack(fill="x", padx=10, pady=5, expand=True)

            ttk.Label(task_frame, text=f"Description:", font=('Arial', 10, 'bold')).pack(anchor="w", padx=5, pady=2)
            desc_text = tk.Text(task_frame, height=4, width=50, wrap=tk.WORD)
            desc_text.insert("1.0", task.description)
            desc_text.config(state=tk.DISABLED)
            desc_text.pack(fill="x", padx=5, pady=2)

            ttk.Label(task_frame, text=f"Max Score: {task.max_score}", font=('Arial', 10)).pack(anchor="w", padx=5)
            ttk.Label(task_frame, text=f"Rule Type: {task.rule_type}", font=('Arial', 10)).pack(anchor="w", padx=5)

            submissions = get_task_submissions(task.id)
            user_submissions = [s for s in submissions if s.user_id == user.id]
            if user_submissions:
                latest_submission = user_submissions[-1]
                status_frame = ttk.Frame(task_frame)
                status_frame.pack(fill="x", padx=5, pady=5)

                ttk.Label(status_frame, text="Latest Submission Status:", font=('Arial', 10, 'bold')).pack(anchor="w")
                ttk.Label(status_frame, text=f"Submitted: {latest_submission.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}").pack(anchor="w")

                if latest_submission.graded_at:
                    ttk.Label(status_frame, text=f"Grade: {latest_submission.score if latest_submission.score is not None else 'Not graded yet'}",
                             font=('Arial', 10)).pack(anchor="w")
                    if latest_submission.similarity_score is not None:
                        ttk.Label(status_frame, text=f"Code Similarity: {latest_submission.similarity_score}%").pack(anchor="w")
                    if latest_submission.output_match is not None:
                        ttk.Label(status_frame, text=f"Output Match: {'Yes' if latest_submission.output_match else 'No'}").pack(anchor="w")
                else:
                    ttk.Label(status_frame, text="Status: Not graded yet", font=('Arial', 10)).pack(anchor="w")

            upload_btn = ttk.Button(
                task_frame,
                text="Upload Solution",
                command=lambda t=task.id: handle_file_upload(t)
            )
            upload_btn.pack(pady=10)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

    if user.is_admin:
        admin_frame = tk.Frame(notebook)
        notebook.add(admin_frame, text="Admin Panel")
        add_task_lf = ttk.LabelFrame(admin_frame, text="Add New Task")
        add_task_lf.pack(padx=10, pady=10, fill="x", expand=True)

        tk.Label(add_task_lf, text="Title:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        title_entry = tk.Entry(add_task_lf, width=50)
        title_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(add_task_lf, text="Description:").grid(row=1, column=0, sticky="nw", padx=5, pady=2)
        description_text = tk.Text(add_task_lf, height=4, width=50)
        description_text.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(add_task_lf, text="Perfect Code:").grid(row=2, column=0, sticky="nw", padx=5, pady=2)
        perfect_code_text = tk.Text(add_task_lf, height=6, width=50)
        perfect_code_text.grid(row=2, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(add_task_lf, text="Expected Output:").grid(row=3, column=0, sticky="nw", padx=5, pady=2)
        expected_output_text = tk.Text(add_task_lf, height=4, width=50)
        expected_output_text.grid(row=3, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(add_task_lf, text="Rule Type:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        rule_type_var = tk.StringVar()
        rule_type_options = ['code', 'output', 'both']
        rule_type_combo = ttk.Combobox(add_task_lf, textvariable=rule_type_var, values=rule_type_options,
                                       state="readonly")
        rule_type_combo.grid(row=4, column=1, sticky="ew", padx=5, pady=2)
        if rule_type_options:
            rule_type_combo.set(rule_type_options[2])

        tk.Label(add_task_lf, text="Max Score:").grid(row=5, column=0, sticky="w", padx=5, pady=2)
        max_score_entry = tk.Entry(add_task_lf, width=10)
        max_score_entry.grid(row=5, column=1, sticky="w", padx=5, pady=2)
        max_score_entry.insert(0, "100")

        add_task_lf.columnconfigure(1, weight=1)

        def handle_add_task_submit():
            """
            Handles the submission of the 'Add New Task' form by an admin.

            Retrieves task details from the input fields, validates them,
            and calls the database function to add the new task.
            Shows success or error messages and clears the form on success.
            """
            title = title_entry.get()
            description = description_text.get("1.0", tk.END).strip()
            perfect_code = perfect_code_text.get("1.0", tk.END).strip()
            expected_output = expected_output_text.get("1.0", tk.END).strip()
            rule_type = rule_type_var.get()
            max_score_str = max_score_entry.get()

            if not all([title, description, perfect_code, rule_type, max_score_str]):
                messagebox.showerror("Input Error",
                                     "Title, Description, Perfect Code, Rule Type, and Max Score are required.")
                return

            try:
                max_score_val = int(max_score_str)
            except ValueError:
                messagebox.showerror("Input Error", "Max Score must be an integer.")
                return

            if rule_type not in rule_type_options:
                messagebox.showerror("Input Error", "Invalid Rule Type selected.")
                return

            if add_task(title, description, perfect_code, expected_output, rule_type, max_score_val, user.id):
                messagebox.showinfo("Success", "Task added successfully!")
                title_entry.delete(0, tk.END)
                description_text.delete("1.0", tk.END)
                perfect_code_text.delete("1.0", tk.END)
                expected_output_text.delete("1.0", tk.END)
                rule_type_combo.set(rule_type_options[2] if rule_type_options else '')
                max_score_entry.delete(0, tk.END)
                max_score_entry.insert(0, "100")
            else:
                messagebox.showerror("Database Error", "Failed to add task. Check application logs.")

        add_button = tk.Button(add_task_lf, text="Add Task", command=handle_add_task_submit)
        add_button.grid(row=6, column=0, columnspan=2, pady=10)

    notebook.pack(expand=1, fill='both')

def handle_login():
    """
    Handles the user login attempt.

    Retrieves username and password from the entry fields, calls the
    login_user function, and shows the main view on success or an error
    message on failure.
    """
    username = username_entry.get()
    password = password_entry.get()
    user = login_user(username, password)
    if user:
        show_main_view(user)
    else:
        messagebox.showerror("Login", "Login failed. Check your username and password.")

def handle_register():
    """
    Handles the user login attempt.

    Retrieves username and password from the entry fields, calls the
    login_user function, and shows the main view on success or an error
    message on failure.
    """
    username = username_entry.get()
    password = password_entry.get()
    is_admin = is_admin_var.get()
    if register_user(username, password, is_admin):
        messagebox.showinfo("Register", f"User '{username}' registered successfully.")
    else:
        messagebox.showerror("Register", f"Registration failed. User '{username}' may already exist.")

def main():
    """
    Main function to initialize and run the Tkinter application.

    Sets up the initial login/registration window and starts the Tkinter
    event loop.
    """
    global username_entry, password_entry, root, is_admin_var
    root = tk.Tk()
    root.title("PPYSDKP")

    tk.Label(root, text="Username:").grid(row=0, column=0, padx=10, pady=5)
    username_entry = tk.Entry(root)
    username_entry.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=5)
    password_entry = tk.Entry(root, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    is_admin_var = tk.BooleanVar()
    tk.Checkbutton(root, text="Register as admin", variable=is_admin_var).grid(row=2, columnspan=2, padx=10, pady=5)

    tk.Button(root, text="Login", command=handle_login).grid(row=3, column=0, padx=10, pady=10)
    tk.Button(root, text="Register", command=handle_register).grid(row=3, column=1, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
