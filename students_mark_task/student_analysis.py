import csv
import os
def read_csv(file_path):
    data = []
    with open(file_path, 'r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader) 
        for row in csv_reader:
            data.append(row)
    return data

def find_topper(subject_index, data):
    subject_marks = [(row[0], int(row[subject_index])) for row in data]
    subject_marks.sort(key=lambda x: x[1], reverse=True)
    return subject_marks[0]

def find_top_students(data):
    total_marks = []
    for row in data:
        marks_sum = sum(map(int, row[1:]))
        total_marks.append((row[0], marks_sum))
    total_marks.sort(key=lambda x: x[1], reverse=True)
    return total_marks[:3]

def print_results(data):
    subjects = ["Maths", "Biology", "English", "Physics", "Chemistry", "Hindi"]
    for i, subject in enumerate(subjects):
        topper = find_topper(i + 1, data)
        print(f"Topper in {subject} is: {topper[0]}")
    top_students = find_top_students(data)
    print()
    print(f"Best students in the class are: {top_students[0][0]}, {top_students[1][0]}, {top_students[2][0]}")

def main():
    current_directory = os.getcwd()
    file_path = os.path.join(current_directory, "Student_mark_list.csv")
    print("file_path:",file_path)
    if os.path.exists(file_path):
        data = read_csv(file_path)
        # print("data:",data)
        print_results(data)
    else:
        print("CSV file not found!")

if __name__ == "__main__":
    main()
