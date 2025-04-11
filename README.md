[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=19140852)
## Python Project: Analyzing a Log File

**Overview**

This project will simulate a scenario you might encounter at a programming job or perhaps as the "IT person" at an organization. You are going to take a simple log file and write python code to analyze it.

This project will not require you to write everything from scratch. Much as in a real world project, you will be using what we know about variables, data types, loops, dictionaries, lists, and functions to adapt some of Python's useful functionality to do the job.

The main takeaway I'd like you to glean from this project is that our fundamental programming building blocks can be used as the basis of many projects with just a little help from either external libraries (or built in ones like we use here), or our own custom code. The fundamentals stay the same, we just extend our Input > Process > Output to use the tools available to meet our needs!

We will use regular expression and file functionality from Python to parse log files to build some simple statistics to help us understand the insights that they contain.

For this project, we will assume that we've been given the regular expression to use by a senior IT person. The starter code will have a function that accepts a line and returns the necessary tuple for you. Here is the regular expression contained therein:

```regex
(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - \"GET (.+) HTTP/1.1\" (\d+)
```

Understanding exactly how this works is beyond the scope of this project, but if you would like more information, feel free to start hereLinks to an external site..

**Regular Expressions**

You will likely be best off to use a regular expression to pull data out of the lines of the log file. The following code will extract the timestamp, ip, url, and status code out of string stored (from the file) in the variable called line. I've included some documentation on regular expressions, but this should be all you need from it to do this job:

```python
for line in log_lines:
    match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - \"GET (.+) HTTP/1.1\" (\d+)", line)
    if match:
        timestamp, ip, url, status_code = match.groups()
```

We will use regular expression and file functionality from Python to parse log files to build some simple statistics to help us understand the insights that they contain.

Regular expressions (regex or regexp) are powerful tools for pattern matching in text. They are essential for tasks like data validation, searching, and text manipulation. In this project, we'll use regex to extract specific data from log lines.

**Key Regex Concepts for this Project:**

*   **Raw Strings (r"..."):** Always use raw strings for regular expressions. This prevents Python from interpreting backslashes in special ways. For example, r"\d" is treated literally as a backslash followed by "d", while "\d" would be interpreted as an escape sequence.

*   **Character Classes:**

    *   `\d`: Matches any digit (0-9).

    *   `\w`: Matches any word character (alphanumeric and underscore).

    *   `\s`: Matches any whitespace character (space, tab, newline).

    *   `.`: Matches any character except a newline.

*   **Quantifiers:**

    *   `+`: Matches one or more occurrences.

    *   `*`: Matches zero or more occurrences.

    *   `?`: Matches zero or one occurrence.

    *   `{n}`: Matches exactly n occurrences.

    *   `{n,m}`: Matches between n and m occurrences.

*   **Anchors:**

    *   `^`: Matches the beginning of a string.

    *   `$`: Matches the end of a string.

*   **Capturing Groups (...):** Parentheses are used to create capturing groups. These allow you to extract specific parts of the matched text. The `match.groups()` method returns a tuple of the captured groups.

**Example Breakdown (from the code):**

```regex
r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - \"GET (.+) HTTP/1.1\" (\d+)"
```

*   `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`: Captures the timestamp (e.g., 2024-10-27 10:30:00).

    *   `\d{4}`: Matches exactly four digits (year).

    *   `-`: Matches the literal hyphen.

    *   `\d{2}`: Matches exactly two digits (month, day, hour, minute, second).

    *   `: Matches a space.

*   `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`: Captures the IP address (e.g., 192.168.1.1).

    *   `\d{1,3}`: Matches one to three digits.

    *   `.`: Matches the literal dot (needs to be escaped with a backslash).

*   `\"GET (.+) HTTP/1.1\"`: Matches the "GET" request and captures the URL.

    *   `\"`: Matches the literal double quote (needs to be escaped).

    *   `GET`: Matches the literal "GET " string.

    *   `(.+)`: Captures one or more of any character (.) – this is the URL. The + is greedy, matching as much as possible.

    *   `HTTP/1.1\"`: Matches the literal " HTTP/1.1" string and closing quote.

*   `(\d+): Captures the status code (e.g., 200, 404).

    *   `\d+`: Matches one or more digits.

**Files**

We will use regular expression and file functionality from Python to parse log files to build some simple statistics to help us understand the insights that they contain. Note that the second code block extracts a list called log\_lines, which can be used with the regular expression above to examine each line individually (and extract the information needed using re's match function.

**Key File Handling Concepts for this Project:**

*   **Opening Files:** The `open()` function is used to open files. We'll use it in "read" mode ("r").

    ```python
    with open(filename, "r") as f:
        # Code to read the file
    ```

    The `with` statement ensures that the file is properly closed even if errors occur.

*   **Reading Lines:** The `readlines()` method reads all lines from the file and returns them as a list of strings.

*   **File Not Found Errors:** It is good practice to handle the possibility that the file doesn't exist using a `try-except` block:

    ```python
    try:
        with open(filename, "r") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        # Handle the error (e.g., exit the program)
    ```


