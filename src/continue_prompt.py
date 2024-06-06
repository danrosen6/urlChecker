def prompt_to_continue():
    while True:
        user_input = input().lower()
        if user_input == 'y':
            return True
        elif user_input == 'n':
            return False
        else:
            print("Invalid input, please enter 'y' or 'n'.")