import subprocess
import json
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os

app = FastAPI(title="WGPL Self-Service Portal")

class OnboardRequest(BaseModel):
    employee_name: str
    department: str
    interface_name: str = "wg0"
    
    # We allow onboarding temporary access
    # e.g., '8h' for contractors, '30d' for normal employees
    expires: str = "30d"

@app.post("/api/vpn/onboard")
async def onboard_employee(req: OnboardRequest, background_tasks: BackgroundTasks):
    """
    Onboards a new employee, generates their VPN peer, and returns the QR code.
    This demonstrates WGPL being used as the backend Control Plane engine.
    """
    # 1. Clean the employee name to be used as a peer name
    safe_name = f"{req.department}_{req.employee_name}".replace(" ", "_")

    try:
        # 2. Add the peer using WGPL CLI (JSON output for easy parsing)
        add_cmd = [
            "wgpl", "-j", "peer", "add", 
            req.interface_name, 
            safe_name, 
            "--expires", req.expires
        ]
        
        result = subprocess.run(add_cmd, capture_output=True, text=True, check=True)
        peer_data = json.loads(result.stdout)
        peer_id = peer_data.get("id")

        # 3. Generate the QR Code image securely using tempfile
        import tempfile
        fd, qr_path = tempfile.mkstemp(suffix=".png")
        os.close(fd) # Close the file descriptor, wgpl will write to the path
        
        qr_cmd = [
            "wgpl", "peer", "qr", 
            peer_id, 
            "-o", qr_path
        ]
        subprocess.run(qr_cmd, check=True)

        # 4. Return the PNG image back to the user's browser/app
        if os.path.exists(qr_path):
            def cleanup_qr():
                if os.path.exists(qr_path):
                    os.remove(qr_path)
            
            background_tasks.add_task(cleanup_qr)
            return FileResponse(
                qr_path, 
                media_type="image/png", 
                filename=f"vpn_profile_{safe_name}.png"
            )
        else:
            raise HTTPException(status_code=500, detail="QR Code generation failed")

    except subprocess.CalledProcessError as e:
        # WGPL prints the error inside the Exception
        raise HTTPException(status_code=400, detail=f"WGPL Error: {e.stderr}")
