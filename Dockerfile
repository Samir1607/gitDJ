# Use an official Python runtime as the base image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the project requirements file to the container
COPY requirements.txt .

# Install the project dependencies
RUN pip install -r requirements.txt

# Copy the entire project directory to the container
COPY . .

# Expose the port on which your Django application runs (default is 8000)
EXPOSE 8000

# Set environment variables (if needed)
# ENV MY_VAR=value

# Run the Django development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
