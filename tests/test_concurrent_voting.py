import pytest
import sqlite3
import threading
import time
import os
import tempfile
import json
import sys
import concurrent.futures
from unittest.mock import patch
from flask import session
import shutil
import random
import string

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from app import app, init_db, generate_unique_code
try:
    DEFAULT_NUM_VOTERS = int(os.environ.get("TEST_NUM_VOTERS", "10"))
except ValueError:
    DEFAULT_NUM_VOTERS = 10

try:
    from extract_voting_codes import extract_codes_from_pdf
    
    pdf_path = "student_voting_codes.pdf"
    if os.path.exists(pdf_path):
        extracted_codes = extract_codes_from_pdf(pdf_path, num_codes=max(DEFAULT_NUM_VOTERS, 10)) 
        if len(extracted_codes) >= 2:
            STUDENT1_CODE = extracted_codes[0]
            STUDENT2_CODE = extracted_codes[1]
            ALL_EXTRACTED_CODES = extracted_codes
        else:
            STUDENT1_CODE = "ABC123"  
            STUDENT2_CODE = "XYZ789"  
            ALL_EXTRACTED_CODES = []
    else:
        STUDENT1_CODE = "ABC123"  
        STUDENT2_CODE = "XYZ789"  
        ALL_EXTRACTED_CODES = []
except ImportError:
    STUDENT1_CODE = "ABC123"  
    STUDENT2_CODE = "XYZ789"  
    ALL_EXTRACTED_CODES = []

print(f"Using voting codes for testing: {STUDENT1_CODE}, {STUDENT2_CODE}")
if ALL_EXTRACTED_CODES:
    print(f"Total extracted codes: {len(ALL_EXTRACTED_CODES)}")
print(f"Default number of concurrent voters for testing: {DEFAULT_NUM_VOTERS}")

MALE_CANDIDATE_ID = 1
FEMALE_CANDIDATE_ID = 2

def generate_test_code():
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(6))

class TestConcurrentVoting:

    @pytest.fixture
    def client(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        
        app.config['TESTING'] = True
        app.config['DATABASE'] = self.db_path
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        app.config['SERVER_NAME'] = 'localhost'  # Required for url_for to work in tests
        
        with app.app_context():
            init_db()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO candidates (name, gender, slogan, description)
                VALUES (?, ?, ?, ?)
            ''', ("John Doe", "Male", "Test Slogan 1", "Test Description 1"))
            
            cursor.execute('''
                INSERT INTO candidates (name, gender, slogan, description)
                VALUES (?, ?, ?, ?)
            ''', ("Jane Doe", "Female", "Test Slogan 2", "Test Description 2"))
            
            cursor.execute('''
                INSERT INTO voters (name, class, section, roll_no, voting_code, is_teacher, has_voted)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ("Student 1", "10", "A", "101", STUDENT1_CODE, 0, 0))
            
            cursor.execute('''
                INSERT INTO voters (name, class, section, roll_no, voting_code, is_teacher, has_voted)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ("Student 2", "10", "B", "102", STUDENT2_CODE, 0, 0))
            
            conn.commit()
            conn.close()
        
        with app.test_client() as client:
            with app.app_context():
                yield client
    
    @pytest.fixture
    def teardown(self):
        yield
        os.close(self.db_fd)
        try:
            os.unlink(self.db_path)
        except PermissionError:
            print(f"Warning: Could not remove temporary database file due to Windows file lock")
    
    def reset_session(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        client.get('/reset_session_for_testing')
    
    def test_verify_codes(self, client, teardown):
        response = client.post('/verify_code', data={'code': STUDENT1_CODE})
        data = json.loads(response.data)
        assert data['success'] is True, f"Code {STUDENT1_CODE} verification failed"
        
        self.reset_session(client)
        
        response = client.post('/verify_code', data={'code': STUDENT2_CODE})
        data = json.loads(response.data)
        assert data['success'] is True, f"Code {STUDENT2_CODE} verification failed"
    
    def voter_process(self, code, voter_name):
        """Simulate the voting process for a single voter using a fresh client"""
        try:
            with app.test_client() as client:
                with app.app_context():
                    response = client.post('/verify_code', data={'code': code})
                    result = json.loads(response.data)
                    assert result['success'] is True, f"{voter_name}: Code verification failed"
                    response = client.post('/cast_vote', 
                                      json={
                                          'male_candidate_id': MALE_CANDIDATE_ID,
                                          'female_candidate_id': FEMALE_CANDIDATE_ID
                                      },
                                      content_type='application/json')
                    
                    result = json.loads(response.data)
                    assert result['success'] is True, f"{voter_name}: Vote casting failed: {result.get('message', 'Unknown error')}"
                    
                    return True
        except Exception as e:
            print(f"{voter_name} Error: {str(e)}")
            return False
    
    def test_concurrent_voting(self, client, teardown):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(self.voter_process, STUDENT1_CODE, "Student 1")
            future2 = executor.submit(self.voter_process, STUDENT2_CODE, "Student 2")
            
            result1 = future1.result()
            result2 = future2.result()
            
            assert result1 is True, "Student 1 voting process failed"
            assert result2 is True, "Student 2 voting process failed"
        
        with app.app_context():
            conn = sqlite3.connect(app.config['DATABASE'])
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT has_voted FROM voters WHERE voting_code = ?', (STUDENT1_CODE,))
            student1 = cursor.fetchone()
            assert student1['has_voted'] == 1, "Student 1 not marked as voted"
            cursor.execute('SELECT has_voted FROM voters WHERE voting_code = ?', (STUDENT2_CODE,))
            student2 = cursor.fetchone()
            assert student2['has_voted'] == 1, "Student 2 not marked as voted"
            
            cursor.execute('SELECT COUNT(*) as count FROM votes WHERE candidate_id = ?', (MALE_CANDIDATE_ID,))
            male_votes = cursor.fetchone()['count']
            assert male_votes == 2, f"Expected 2 votes for male candidate, got {male_votes}"
            
            cursor.execute('SELECT COUNT(*) as count FROM votes WHERE candidate_id = ?', (FEMALE_CANDIDATE_ID,))
            female_votes = cursor.fetchone()['count']
            assert female_votes == 2, f"Expected 2 votes for female candidate, got {female_votes}"
            
            conn.close()
    
    def setup_multiple_voters(self, num_voters):
        db_fd, db_path = tempfile.mkstemp()
        
        self.multi_db_fd = db_fd
        self.multi_db_path = db_path
        app.config['TESTING'] = True
        app.config['DATABASE'] = db_path
        app.config['WTF_CSRF_ENABLED'] = False
        
        voter_codes = []
        
        with app.app_context():
            init_db()
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO candidates (name, gender, slogan, description)
                VALUES (?, ?, ?, ?)
            ''', ("Male Candidate", "Male", "Test Slogan", "Description"))
            
            cursor.execute('''
                INSERT INTO candidates (name, gender, slogan, description)
                VALUES (?, ?, ?, ?)
            ''', ("Female Candidate", "Female", "Test Slogan", "Description"))
            
            for i in range(num_voters):
                if i < len(ALL_EXTRACTED_CODES):
                    code = ALL_EXTRACTED_CODES[i]
                else:
                    code = generate_test_code()
                    
                    while code in voter_codes:
                        code = generate_test_code()
                
                voter_codes.append(code)
                
                cursor.execute('''
                    INSERT INTO voters (name, class, section, roll_no, voting_code, is_teacher, has_voted)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (f"Student {i+1}", "10", chr(65 + (i % 26)), f"{i+101}", code, 0, 0))
            
            conn.commit()
            conn.close()
        
        return voter_codes, db_path
    
    def test_multiple_concurrent_voters(self):
        num_voters = DEFAULT_NUM_VOTERS
        
        voter_codes, db_path = self.setup_multiple_voters(num_voters)
        
        try:
            print(f"Starting concurrent voting test with {num_voters} voters...")
            start_time = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_voters) as executor:
                futures = []
                for i, code in enumerate(voter_codes):
                    futures.append(executor.submit(self.voter_process, code, f"Student {i+1}"))
                results = [future.result() for future in futures]
                
                for i, result in enumerate(results):
                    assert result is True, f"Student {i+1} voting process failed"
            
            elapsed_time = time.time() - start_time
            
            with app.app_context():
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) as count FROM voters WHERE has_voted = 1')
                voted_count = cursor.fetchone()['count']
                assert voted_count == num_voters, f"Expected {num_voters} voted students, got {voted_count}"
                
                cursor.execute('SELECT COUNT(*) as count FROM votes WHERE candidate_id = ?', (MALE_CANDIDATE_ID,))
                male_votes = cursor.fetchone()['count']
                assert male_votes == num_voters, f"Expected {num_voters} votes for male candidate, got {male_votes}"
                
                cursor.execute('SELECT COUNT(*) as count FROM votes WHERE candidate_id = ?', (FEMALE_CANDIDATE_ID,))
                female_votes = cursor.fetchone()['count']
                assert female_votes == num_voters, f"Expected {num_voters} votes for female candidate, got {female_votes}"
                
                conn.close()
                
            print(f"✓ Successfully tested concurrent voting with {num_voters} voters")
            print(f"  Time taken: {elapsed_time:.2f} seconds")
            print(f"  Average time per vote: {elapsed_time/num_voters:.4f} seconds")
            
        finally:
            os.close(self.multi_db_fd)
            try:
                os.unlink(self.multi_db_path)
            except PermissionError:
                print(f"Warning: Could not remove multi-voter database file due to Windows file lock")
    
    def test_double_voting_prevention(self, client, teardown):
        
        response = client.post('/verify_code', data={'code': STUDENT1_CODE})
        assert json.loads(response.data)['success'] is True
        
        response = client.post('/cast_vote', 
                          json={
                              'male_candidate_id': MALE_CANDIDATE_ID,
                              'female_candidate_id': FEMALE_CANDIDATE_ID
                          },
                          content_type='application/json')
        assert json.loads(response.data)['success'] is True
        
        self.reset_session(client)
        
        response = client.post('/verify_code', data={'code': STUDENT1_CODE})
        result = json.loads(response.data)
        
        assert result['success'] is False
        assert "already voted" in result.get('message', '').lower()


if __name__ == "__main__":
    pytest.main(["-xvs", "test_concurrent_voting.py"]) 