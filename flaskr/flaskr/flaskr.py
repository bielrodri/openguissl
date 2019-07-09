# all the imports
# coding: utf-8
import os
import sqlite3
import subprocess
from flask import Flask, request, session, g, redirect, url_for, abort, \
    render_template, flash, json, make_response

from werkzeug.utils import secure_filename
from flask import send_from_directory

import sys
if sys.version_info.major < 3:
    reload(sys)
sys.setdefaultencoding('utf8')

# ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)  # create the application instance :)
app.config.from_object(__name__)  # load config from this file , flaskr.py

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads_SI_openguissl')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Load default config and override config from an environment variable
app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'flaskr.db'),
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='default'
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

# from werkzeug import SharedDataMiddleware
# app.add_url_rule('/uploads/<filename>', 'uploaded_file',
#                  build_only=True)
# app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
#     '/uploads':  app.config['UPLOAD_FOLDER']
# })


def get_ciphernames():
    ciphernames = []
    ciphernames.append({'name': 'aes256', 'value': '-aes256'})
    ciphernames.append({'name': 'des-ecb', 'value': '-des-ecb'})
    ciphernames.append({'name': 'rc4', 'value': '-rc4'})
    return ciphernames


def get_HashAlgorithms():
    hashAlg = []
    hashAlg.append({'name': 'md5', 'value': '-md5'})
    hashAlg.append({'name': 'sha1', 'value': '-sha1'})
    hashAlg.append({'name': 'sha256', 'value': '-sha256'})
    return hashAlg


def get_HMACAlgorithms():
    HMACAlg = []
    HMACAlg.append({'name': 'md5', 'value': '-md5'})
    HMACAlg.append({'name': 'sha1', 'value': '-sha1'})
    HMACAlg.append({'name': 'sha256', 'value': '-sha256'})
    return HMACAlg


app.jinja_env.globals.update(get_ciphernames=get_ciphernames)
app.jinja_env.globals.update(get_HashAlgorithms=get_HashAlgorithms)
app.jinja_env.globals.update(get_HMACAlgorithms=get_HMACAlgorithms)


@app.route('/')
def index():
    return render_template('index.html')
    

def run_command(cmd, isGenRSA=False):
    '''
        cmd         A string of commands separated by spaces 
        isGenRSA    A boolean to fix an error with generating RSA keys,
                    for some reason the command returns stderr, though
                    it's not an error, it's a message saying it's generating
                    the private key.
    '''
    p = subprocess.Popen(
        cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    out, err = p.communicate()

    if err and not isGenRSA:
        raise RuntimeError(err)

    return out

def cifrar(cipherName, key, dec, inFile, outFile, iv=None):
    cmd = "openssl enc " + cipherName + " " + dec + "-K " + key + " -in " + inFile + " -out " + outFile
    if cipherName == "-aes256":
        cmd = cmd + " -iv " + iv
    run_command(cmd)
    return 


@app.route('/cifrarFicheiro', methods=['GET', 'POST'])
def cifrarFicheiro(cameFrom=None):
    iv = request.form.get('iv', 0)
    if request.method == 'POST':
        if not cameFrom:
            key = request.form.get('key', None)
            selCiphername = request.form.get('selCiphername', None)
            outName = request.form.get('outName', None)

            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return render_template("cipherFile.html", key=key)
            
            fileIn = request.files['file']
            
            if not key:
                flash('Chave inválida')
                return render_template("cipherFile.html", file=fileIn.filename, key=key,
                                       selCiphername=selCiphername, iv=iv, outName=outName)

            if fileIn.filename == '':
                flash('Ficheiro não selecionado')
                return render_template("cipherFile.html", file=fileIn.filename, key=key,
                                       selCiphername=selCiphername, iv=iv, outName=outName)

            # if fileIn and allowed_file(fileIn.filename):
            if fileIn:
                filename = secure_filename(fileIn.filename)
                fileInPath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                fileInPath = os.path.abspath(fileInPath)
                
                fileIn.save(fileInPath)
                
                outName = request.form.get('outName', None)
                outName_with_ext = outName + "." + selCiphername[1:]

                fileOutPath = os.path.join(app.config['UPLOAD_FOLDER'], outName_with_ext)
                fileOutPath = os.path.abspath(fileOutPath)

                decifrar = request.form.get('decifrar', None)
                if (decifrar):
                    dec = "-d "
                else:
                    dec = ""
                cifrar(cipherName=selCiphername, key=key, dec=dec, inFile=fileInPath, outFile=fileOutPath,
                       iv=iv)
                
                fileOut = open(fileOutPath, "r")
                fileOut_contents = fileOut.read()

                # result = transform(fileOut_contents)
                result = fileOut_contents

                response = make_response(result)
                response.headers["Content-Disposition"] = "attachment; filename=" + outName_with_ext
                return response

    return render_template("cipherFile.html")


def genKey(keyType, numBytes):
    cmd = "openssl rand " + keyType + " " + numBytes
    key = run_command(cmd)
    return key


@app.route('/gerarChaves', methods=['GET', 'POST'])
def gerarChaves(cameFrom=None):
    keyType = request.form.get('keyType', None)
    numBytes = request.form.get('numBytes', None)
    if not keyType or not numBytes:
        return render_template("genRandKey.html", keyType=keyType, numBytes=numBytes)
    key = genKey(keyType=keyType, numBytes=numBytes)
    if not cameFrom:
        return render_template("genRandKey.html", key=key, keyType=keyType, numBytes=numBytes)




def dgstHashHMAC(hashAlg, inFile, hmac="", hmacKey=""):
    cmd = "openssl dgst " + hashAlg + hmac + hmacKey + " -hex " + inFile
    return run_command(cmd)


@app.route('/calculateHash', methods=['GET', 'POST'])
def calcHash():
    if request.method == 'POST':
        selHashAlg = request.form.get('selHashAlg', None)

        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return render_template("calcHash.html",
                                   selHashAlg=selHashAlg)

        fileIn = request.files['file']

        if fileIn.filename == '':
            flash('Ficheiro não selecionado')
            return render_template("calcHash.html", file=fileIn.filename,
                                    selHashAlg=selHashAlg)
        
        # if fileIn and allowed_file(fileIn.filename):
        if fileIn:
            filename = secure_filename(fileIn.filename)
            fileInPath = os.path.join(
                app.config['UPLOAD_FOLDER'], filename)
            fileInPath = os.path.abspath(fileInPath)

            fileIn.save(fileInPath)

            outName_with_ext = filename + "." + selHashAlg[1:]

            fileOutPath = os.path.join(app.config['UPLOAD_FOLDER'], outName_with_ext)
            fileOutPath = os.path.abspath(fileOutPath)


            
            calculatedHash = dgstHashHMAC(hashAlg=selHashAlg, inFile=fileInPath).split("=")[1]
            downloadFic = request.form.get('downloadFic', None)
            if (downloadFic):
                response = make_response(calculatedHash)
                response.headers["Content-Disposition"] = "attachment; filename=" + \
                    outName_with_ext
                return response
            else:
                flash("Hash calculado: " + calculatedHash)
                return render_template("calcHash.html", file=fileIn.filename,
                                       selHashAlg=selHashAlg)
    return render_template("calcHash.html")


@app.route('/calculateHMAC', methods=['GET', 'POST'])
def calcHMAC():
    if request.method == 'POST':
        selHMACAlg = request.form.get('selHMACAlg', None)
        key = request.form.get('key', None)

        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return render_template("calcHmac.html",
                                   selHMACAlg=selHMACAlg, key=key)

        fileIn = request.files['file']

        if fileIn.filename == '':
            flash('Ficheiro não selecionado')
            return render_template("calcHmac.html", file=fileIn.filename,
                                   selHMACAlg=selHMACAlg, key=key)

        # if fileIn and allowed_file(fileIn.filename):
        if fileIn:
            filename = secure_filename(fileIn.filename)
            fileInPath = os.path.join(
                app.config['UPLOAD_FOLDER'], filename)
            fileInPath = os.path.abspath(fileInPath)

            fileIn.save(fileInPath)

            outName_with_ext = filename + "." + selHMACAlg[1:]

            fileOutPath = os.path.join(
                app.config['UPLOAD_FOLDER'], outName_with_ext)
            fileOutPath = os.path.abspath(fileOutPath)

            calculatedHash = dgstHashHMAC(hashAlg=selHMACAlg, inFile=fileInPath, 
                                          hmac=" -hmac ", hmacKey=key).split("=")[1]
            downloadFic = request.form.get('downloadFic', None)
            if (downloadFic):
                response = make_response(calculatedHash)
                response.headers["Content-Disposition"] = "attachment; filename=" + \
                    outName_with_ext
                return response
            else:
                flash("HMAC calculado: " + calculatedHash)
                return render_template("calcHmac.html", file=fileIn.filename,
                                       selHMACAlg=selHMACAlg, key=key)
    return render_template("calcHmac.html")



#----------------------------------------------------------------------------------------------#
#---------------------------------------RSA KEYS-----------------------------------------------#
#----------------------------------------------------------------------------------------------#

def generateRSAKeyPair(fileOutPath):
    # cmd = "openssl genrsa -out " + fileOutPath + " 2048"
    cmd = "openssl genrsa 2048"
    return run_command(cmd, isGenRSA=True)


@app.route('/genRSAkeys', methods=['GET', 'POST'])
def genRSAkeys():
    outName = request.form.get('outName', None)
    if request.method == 'POST':
        if not outName:
            flash('Ficheiro de saida não selecionado')
            return render_template("genRSAKeyPair.html", outName=outName)
            
        outName_with_ext = outName + ".pem"
        fileOutPath = os.path.join(
            app.config['UPLOAD_FOLDER'], outName_with_ext)
        fileOutPath = os.path.abspath(fileOutPath)

        RSAKeyPair = generateRSAKeyPair(fileOutPath=fileOutPath)
        response = make_response(RSAKeyPair)
        response.headers["Content-Disposition"] = "attachment; filename=" + \
            outName_with_ext
        return response
    return render_template("genRSAKeyPair.html", outName=outName)

#----------------------------------------------------------------------------------------------#
#------------------------------------GET PUBLIC RSA KEYS---------------------------------------#
#----------------------------------------------------------------------------------------------#
def get_pubKey(fileInPath):
    cmd = "openssl rsa -in " + fileInPath + " -pubout"
    return run_command(cmd, isGenRSA=True)


@app.route('/getPubKey', methods=['GET', 'POST'])
def getPubKey():
    outName = request.form.get('outName', None)
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return render_template("getPubKey.html", outName=outName)

        fileIn = request.files['file']

        if fileIn.filename == '':
            flash('Ficheiro não selecionado')
            return render_template("getPubKey.html", file=fileIn.filename, outName=outName)

        # if fileIn and allowed_file(fileIn.filename):
        if fileIn:
            filename = secure_filename(fileIn.filename)
            fileInPath = os.path.join(
                app.config['UPLOAD_FOLDER'], filename)
            fileInPath = os.path.abspath(fileInPath)

            fileIn.save(fileInPath)
                

            RSAPubKey = get_pubKey(fileInPath=fileInPath)

            downloadFic = request.form.get('downloadFic', None)
            if (downloadFic):
                outName_with_ext = outName + ".pem"
                response = make_response(RSAPubKey)
                response.headers["Content-Disposition"] = "attachment; filename=" + \
                    outName_with_ext
                return response
            else:
                flash("Chave Pública: " + RSAPubKey)
                return render_template("getPubKey.html", file=fileIn.filename,outName=outName)
    return render_template("getPubKey.html", outName=outName)


#----------------------------------------------------------------------------------------------#
#------------------------------------DIGITAL SIGNATURE-----------------------------------------#
#----------------------------------------------------------------------------------------------#

#----------------------------------------------------------------------------------------------#
#----------------------------------------SIGN FILE---------------------------------------------#
#----------------------------------------------------------------------------------------------#
def do_signFile(filePrivKeyPath, fileToSignPath, fileSigOutPath):
    # "openssl dgst -sha256 -sign privatekey.pem -out signature.sign file.txt"
    # "openssl dgst -sha256 -sign myprivate.pem -out filesign.sign originalfile.txt"
    # "openssl dgst -sha256 -sign my.key -out in.txt.sha256 in.txt"
    cmd = "openssl dgst -sha256 -sign " + filePrivKeyPath + " -out " + fileSigOutPath + " " + fileToSignPath
    run_command(cmd)
    return


@app.route('/signFile', methods=['GET', 'POST'])
def signFile():
    outName = request.form.get('outName', None)
    if request.method == 'POST':
        # check if the post request has the file part
        if 'filePrivKey' not in request.files or 'fileToSign' not in request.files:
            flash('No file part')
            return render_template("signFile.html", outName=outName)

        filePrivKey = request.files['filePrivKey']

        if filePrivKey.filename == '':
            flash('Ficheiro não selecionado')
            return render_template("signFile.html", outName=outName)

        fileToSign = request.files['fileToSign']

        if fileToSign.filename == '':
            flash('Ficheiro não selecionado')
            return render_template("signFile.html", outName=outName)

        if fileToSign and filePrivKey:
            fileToSignName = secure_filename(fileToSign.filename)
            fileToSignPath = os.path.join(
                app.config['UPLOAD_FOLDER'], fileToSignName)
            fileToSignPath = os.path.abspath(fileToSignPath)

            fileToSign.save(fileToSignPath)

            filePrivKeyName = secure_filename(filePrivKey.filename)
            filePrivKeyPath = os.path.join(
                app.config['UPLOAD_FOLDER'], filePrivKeyName)
            filePrivKeyPath = os.path.abspath(filePrivKeyPath)

            filePrivKey.save(filePrivKeyPath)

            outName_with_ext = outName + ".sign"
            fileSigOutPath = os.path.join(app.config['UPLOAD_FOLDER'], outName_with_ext)
            fileSigOutPath = os.path.abspath(fileSigOutPath)

            do_signFile(filePrivKeyPath=filePrivKeyPath,
                        fileToSignPath=fileToSignPath, fileSigOutPath=fileSigOutPath)

            fileSigOut = open(fileSigOutPath, "r")
            fileSigOut_contents = fileSigOut.read()

            response = make_response(fileSigOut_contents)
            response.headers["Content-Disposition"] = "attachment; filename=" + outName_with_ext
            return response
    return render_template("signFile.html", outName=outName)



#----------------------------------------------------------------------------------------------#
#-------------------------------------VERIFY SIGNATURE-----------------------------------------#
#----------------------------------------------------------------------------------------------#
def do_VerifySign(filePubKeyPath, fileToVerifyPath, fileSigPath):
    # "openssl dgst -sha256 -verify publickey.pem -signature signature.sign originalfile.txt"
    ''' The return is either:
            For failure: Verification Failure
            For success: Verified OK
    '''
    cmd = "openssl dgst -sha256 -verify " + filePubKeyPath + " -signature " + fileSigPath + " " + fileToVerifyPath
    return run_command(cmd)


@app.route('/verifySign', methods=['GET', 'POST'])
def verifySign():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'filePubKey' not in request.files or 'fileToVerify' not in request.files or 'fileSig' not in request.files:
            flash('No file part')
            return render_template("verifySign.html")

        filePubKey = request.files['filePubKey']
        if filePubKey.filename == '':
            flash('Ficheiro não selecionado')
            return render_template("verifySign.html")

        fileSig = request.files['fileSig']
        if fileSig.filename == '':
            flash('Ficheiro não selecionado')
            return render_template("verifySign.html")

        fileToVerify = request.files['fileToVerify']
        if fileToVerify.filename == '':
            flash('Ficheiro não selecionado')
            return render_template("verifySign.html")

        if fileToVerify and filePubKey and fileSig:
            fileToVerifyName = secure_filename(fileToVerify.filename)
            fileToVerifyPath = os.path.join(
                app.config['UPLOAD_FOLDER'], fileToVerifyName)
            fileToVerifyPath = os.path.abspath(fileToVerifyPath)

            fileToVerify.save(fileToVerifyPath)

            filePubKeyName = secure_filename(filePubKey.filename)
            filePubKeyPath = os.path.join(
                app.config['UPLOAD_FOLDER'], filePubKeyName)
            filePubKeyPath = os.path.abspath(filePubKeyPath)

            filePubKey.save(filePubKeyPath)

            fileSigName = secure_filename(fileSig.filename)
            fileSigPath = os.path.join(
                app.config['UPLOAD_FOLDER'], fileSigName)
            fileSigPath = os.path.abspath(fileSigPath)

            fileSig.save(fileSigPath)

            sigVerification = do_VerifySign(filePubKeyPath=filePubKeyPath,
                                            fileToVerifyPath=fileToVerifyPath, fileSigPath=fileSigPath)

            flash("Resposta da verificação pelo openssl: " + sigVerification)
            return render_template("verifySign.html")

    return render_template("verifySign.html")
