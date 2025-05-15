import os
import sys
import PyPDF2
import re
import random
import string

def extract_codes_from_pdf(pdf_path, num_codes=2):
    """
    Extract voting codes from the provided PDF file.
    
    Args:
        pdf_path (str): Path to the PDF file
        num_codes (int): Number of codes to extract
        
    Returns:
        list: List of extracted codes
    """
    try:
        codes = []
        
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            
            for page in pdf_reader.pages:
                text = page.extract_text()
                
                possible_codes = re.findall(r'\b[A-Z0-9]{6,8}\b', text)
                
                codes.extend(possible_codes)
                
                if len(codes) >= num_codes:
                    break
        
        if 0 < len(codes) < num_codes:
            print(f"Found only {len(codes)} codes in the PDF, generating {num_codes - len(codes)} additional codes for testing")
            generated_codes = generate_additional_codes(num_codes - len(codes), existing_codes=codes)
            codes.extend(generated_codes)
            
        elif len(codes) == 0:
            print(f"No codes found in the PDF, generating {num_codes} test codes")
            codes = generate_additional_codes(num_codes)
        
        return codes[:num_codes]
    
    except Exception as e:
        print(f"Error extracting codes: {str(e)}")
        return generate_additional_codes(num_codes)

def generate_additional_codes(count, existing_codes=None):
    """Generate additional random codes for testing"""
    if existing_codes is None:
        existing_codes = []
        
    chars = string.ascii_uppercase + string.digits
    generated_codes = []
    
    while len(generated_codes) < count:
        code = ''.join(random.choice(chars) for _ in range(6))
        if code not in existing_codes and code not in generated_codes:
            generated_codes.append(code)
    
    return generated_codes

if __name__ == "__main__":
    pdf_path = "student_voting_codes.pdf"
    
    num_codes = 10
    if len(sys.argv) > 1:
        try:
            num_codes = int(sys.argv[1])
        except ValueError:
            print(f"Invalid number of codes specified, using default: {num_codes}")
    
    if not os.path.exists(pdf_path):
        print(f"PDF file not found: {pdf_path}")
        sys.exit(1)
    
    codes = extract_codes_from_pdf(pdf_path, num_codes)
    
    if not codes:
        print("No codes found or generated.")
        print("Using default test codes: ABC123, XYZ789")
    else:
        print(f"Found/generated {len(codes)} codes:")
        for i, code in enumerate(codes):
            print(f"CODE {i+1}: {code}")
        
        with open("voting_codes.py", "w") as f:
            f.write("# Automatically extracted/generated voting codes from PDF\n\n")
            for i, code in enumerate(codes):
                f.write(f"STUDENT{i+1}_CODE = \"{code}\"\n")
            
            f.write("\n# List of all codes\n")
            f.write("ALL_CODES = [\n")
            for i, code in enumerate(codes):
                f.write(f"    \"{code}\",\n")
            f.write("]\n")
            
        print("\nCodes saved to voting_codes.py") 