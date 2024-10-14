import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
import tkinter.ttk as ttk

# Global variables
initial_window = None
data_window = None
tree = None

def show_initial_window():
    """Show the initial window with the start button in a maximized state."""
    global initial_window
    initial_window = tk.Tk()
    initial_window.title("NIDS Start")

    # Maximize the window
    initial_window.state('zoomed')  # Set the window to maximized state
    initial_window.update_idletasks()  # Ensure the window updates immediately

    # Create a frame to center the button
    frame = tk.Frame(initial_window)
    frame.place(relx=0.5, rely=0.5, anchor='center')

    start_button = tk.Button(frame, text="Start Packet Capture", command=open_file_browser, font=("Arial", 18))
    start_button.pack(pady=30, padx=30)

    # Handle window close event
    initial_window.protocol("WM_DELETE_WINDOW", on_closing_initial_window)
    initial_window.mainloop()

def open_file_browser():
    """Open file dialog to select a CSV file and display its first five rows."""
    try:
        # Open file dialog to choose a CSV file
        csv_file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if csv_file_path:
            # Display the CSV file data in a new window
            display_csv_file(csv_file_path)
    except Exception as e:
        print(f"Error opening file: {e}")
        messagebox.showerror("Error", f"An error occurred while opening the file: {e}")

def display_csv_file(file_path):
    """Display the contents of the CSV file in a new maximized window."""
    global data_window, tree

    try:
        # Load only the first five rows of the CSV file
        df = pd.read_csv(file_path, nrows=100)
        
        # Create a new window to display the data
        if data_window:
            data_window.destroy()
        
        data_window = tk.Toplevel()
        data_window.title("CSV Data")

        # Maximize the window
        data_window.state('zoomed')  # Set the window to maximized state
        data_window.update_idletasks()  # Ensure the window updates immediately

        # Create a menu bar
        menu = tk.Menu(data_window)
        data_window.config(menu=menu)
        
        # File Menu
        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save As", command=save_as)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=on_closing_data_window)
        
        # View Menu
        view_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Zoom In", command=lambda: adjust_zoom(1.1))
        view_menu.add_command(label="Zoom Out", command=lambda: adjust_zoom(0.9))
        
        # Settings Menu
        settings_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Configure", command=open_config_settings)
        
        # Create Treeview widget to show the CSV data
        tree = ttk.Treeview(data_window)
        tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        vsb = ttk.Scrollbar(tree, orient="vertical", command=tree.yview)
        vsb.pack(side='right', fill='y')
        tree.configure(yscrollcommand=vsb.set)

        hsb = ttk.Scrollbar(tree, orient="horizontal", command=tree.xview)
        hsb.pack(side='bottom', fill='x')
        tree.configure(xscrollcommand=hsb.set)

        # Display the first five rows
        columns = df.columns.tolist()
        tree.configure(columns=columns, show='headings')

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)

        for item in tree.get_children():
            tree.delete(item)

        for _, row in df.iterrows():
            tree.insert("", tk.END, values=row.tolist())

    except Exception as e:
        print(f"Error displaying CSV file: {e}")
        messagebox.showerror("Error", f"An error occurred while displaying the CSV file: {e}")

def save_as():
    """Save the displayed CSV data to a file."""
    try:
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if file_path:
            global tree
            # Get data from Treeview
            columns = [tree.heading(col, 'text') for col in tree["columns"]]
            rows = [tree.item(child)["values"] for child in tree.get_children()]

            # Create DataFrame and save to CSV
            df = pd.DataFrame(rows, columns=columns)
            df.to_csv(file_path, index=False)
            messagebox.showinfo("Saved", f"Data saved to {file_path}")

    except Exception as e:
        print(f"Error saving data: {e}")
        messagebox.showerror("Error", f"An error occurred while saving data: {e}")

def adjust_zoom(factor):
    """Adjust the zoom level of the Treeview widget."""
    try:
        for col in tree["columns"]:
            current_width = tree.column(col, option="width")
            new_width = int(current_width * factor)
            tree.column(col, width=new_width)
    except Exception as e:
        print(f"Error adjusting zoom: {e}")
        messagebox.showerror("Error", f"An error occurred while adjusting zoom: {e}")

def open_config_settings():
    """Open configuration settings window."""
    settings_window = tk.Toplevel()
    settings_window.title("Configuration Settings")
    settings_window.geometry('300x200')
    
    tk.Label(settings_window, text="Settings go here...").pack(pady=20)

def on_closing_initial_window():
    """Handle the closing of the initial window."""
    if initial_window:
        initial_window.destroy()

def on_closing_data_window():
    """Handle the closing of the data window."""
    if initial_window:
        initial_window.destroy()
    if data_window:
        data_window.destroy()

# Start with the initial window
show_initial_window()
