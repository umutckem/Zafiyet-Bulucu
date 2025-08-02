import sys
import io
from contextlib import contextmanager

class OutputCapture:
    def __init__(self):
        self.output = ""
        
    def capture_print(self, func, *args, **kwargs):
        """Print çıktılarını yakalar ve string olarak döner"""
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        
        try:
            result = func(*args, **kwargs)
            captured_output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            return captured_output, result
        except Exception as e:
            sys.stdout = old_stdout
            raise e
    
    @contextmanager
    def capture_output(self):
        """Context manager olarak kullanım için"""
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            yield sys.stdout
        finally:
            captured_output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            self.output = captured_output 