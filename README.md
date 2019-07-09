# openguissl

* Observations:
  * A virtual environment must be installed to use this application. 
  * This application had been tested just in Linux system.

Follow the steps below to use the application

* 1º Step:\
activate the virtual environment
. venv/bin/activate

* 2º Step:\
Go to 'flaskr/flaskr' directory through command line

* 3º Step:\
At the first use of the application the requirements must be installed:
  - pip install -r requirements.txt

* 4º Step:\
 Once the requirements is installed follow the commands below: 
  * export FLASK_APP=flaskr.flaskr
  * pip install --editable .
  * export FLASK_APP=flaskr            
  * export FLASK_DEBUG=true
  * flask run

* 5º Step:\
An URL must be generated so you can access this in your browser
