# algorithms/morse_code/morse_code.py

class MorseCode:
    # Morse code dictionary
    MORSE_CODE_DICT = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '0': '-----', ', ': '--..--', '.': '.-.-.-', '?': '..--..',
        '/': '-..-.', '-': '-....-', '(': '-.--.', ')': '-.--.-',
        ' ': '/'  # space is represented as forward slash in Morse
    }
    
    # Inverse dictionary for decoding
    MORSE_CODE_DICT_INV = {v: k for k, v in MORSE_CODE_DICT.items()}

    @staticmethod
    def encrypt(message):
        """
        Convert text to Morse code
        """
        cipher = ''
        message = message.upper()
        
        for char in message:
            if char in MorseCode.MORSE_CODE_DICT:
                cipher += MorseCode.MORSE_CODE_DICT[char] + ' '
            else:
                # For characters not in our dictionary
                cipher += char + ' '
                
        return cipher.strip()

    @staticmethod
    def decrypt(morse_code):
        """
        Convert Morse code to text
        """
        morse_code += ' '  # Add extra space to catch the last morse character
        message = ''
        current_code = ''
        
        for symbol in morse_code:
            # Check for space (which separates morse characters)
            if symbol != ' ':
                current_code += symbol
            else:
                # Space found, which means end of a morse character
                if current_code:
                    if current_code in MorseCode.MORSE_CODE_DICT_INV:
                        message += MorseCode.MORSE_CODE_DICT_INV[current_code]
                    else:
                        # If the code doesn't exist in our dictionary
                        message += '<unknown>'
                    current_code = ''
                
                # If we encounter double space (meaning word separation in morse)
                if symbol == '/' or (len(morse_code) > 1 and morse_code[1] == ' '):
                    message += ' '
                    morse_code = morse_code[1:]  # Skip the next space
        
        return message