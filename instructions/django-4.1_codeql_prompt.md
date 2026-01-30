## Objective
Search the codebase for form widget implementations that handle file uploads with specific focus on identifying:
1. How file input widgets process and validate uploaded files
2. Whether widgets support or handle multiple file uploads
3. Validation logic applied to file inputs

NOTE: * (wildcard) can be used for matching relevant searches

## Search Strategy

### Step 1: Locate File Input Widget Implementations
Find form widget classes that handle file uploads:
- Search for `*File*` class definitions and its subclasses (* means wildcard)
- Look for `*FileInput*` widget implementations
- Identify any custom widget classes extending file input widgets
- Check initialization methods of widgets

### Step 2: Analyze Multiple File Handling
Search for code patterns related to multiple file processing:
- Look for conditions checking for `*multiple*` attribute on file input widgets
- Find code that processes lists or multiple values from form data
- Search for iteration patterns over multiple files or uploaded items
- Look for attributes like `*multiple*` in widget classes

### Step 3: Identify File Validation Points
Find where file validation occurs:
- Locate where individual files are validated
- Search for form field cleaning methods that process uploaded files
- Find validation logic that processes file lists or multiple uploads
- Look for conditional statements checking file counts or states

### Step 4: Track File Data Flow
Follow the flow of file data:
- How are files extracted from request data
- How are they passed to validation methods
- Whether validation happens before or after collecting all files
- If only certain files (like the last one) are validated

## Key Code Patterns to Search For
- Widget attribute definitions
- HTML attribute handling in widget rendering
- Form field cleaning method implementations
- File list iteration and filtering
- Exception raising for unsupported configurations

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find File and FileInput class objects
 * @description Finds all instantiations and references to File or FileInput class objects
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-file-input-objects
 * @tags files
 *       input
 *       security
 */

import python

predicate isFileClass(string name) {
  name in [
    "File",
    "FileInput",
    "UploadFile",
    "UploadedFile",
    "InMemoryUploadedFile",
    "TemporaryUploadedFile"
  ]
}

from Call c, string className
where
  (
    // Direct instantiation: File(...) or FileInput(...)
    c.getFunc().(Name).getId() = className
    and isFileClass(className)
  )
  or
  (
    // Attribute access instantiation: module.File(...) or module.FileInput(...)
    c.getFunc().(Attribute).getName() = className
    and isFileClass(className)
  )
select c, "File class instantiation found: " + className
```

```ql
/**
 * @name Find File and FileInput in function parameters
 * @description Finds function parameters that accept File or FileInput objects (common in FastAPI, Django, Flask)
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-file-input-parameters
 * @tags files
 *       input
 *       security
 *       api
 */

import python

predicate isFileClass(string name) {
  name in [
    "File",
    "FileInput",
    "UploadFile",
    "UploadedFile",
    "InMemoryUploadedFile",
    "TemporaryUploadedFile"
  ]
}

from Function f, Parameter p, string className
where
  p = f.getAnArg()
  and
  (
    // Type annotation: def func(file: UploadFile)
    p.getAnnotation().(Name).getId() = className
    or
    // Attribute annotation: def func(file: fastapi.UploadFile)
    p.getAnnotation().(Attribute).getName() = className
  )
  and isFileClass(className)
select p, "Function parameter with File type: " + className + " in function " + f.getName()
```
