const base64url = require('base64url');


$ = require('jquery');
jQuery = $;

Config = require('lib/config.js');

// loginViewModel constructor
let UserUpdateViewModel = function(){
    let _this = this;
    this._authenticatorListIndex = 0;
    $(document).ready(function() {
        //対応するViewがDOMに存在する場合
        if($('#user-update-view').length){
            _this.setupEventListeners();
        }
    });
};

UserUpdateViewModel.prototype.addCredential = function (){
    let _this = this;
    let challengeBase64 = $("meta[name='_challenge']").attr("content");
    let challenge = base64url.toBuffer(challengeBase64);
    let userHandle = base64url.toBuffer($('#userHandle').val());
    let makePublicKeyCredentialOptions = {
        // Relying Party:
        rp: {
            name: "spring-security-webauthn sample"
        },
        // User:
        user: {
            id: userHandle,
            name: $('#emailAddress').val(),
            displayName: $('#firstName').val() + " " + $('#lastName').val(),
            icon: null
        },
        challenge: challenge,
        pubKeyCredParams: [
            {
                alg: -7,
                type: "public-key"
            },
            {
                alg: -257, //Windows Hello
                type: "public-key"
            }
        ],
        //timeout
        //excludeCredentials = []
        authenticatorSelection: {
            requireResidentKey: $('#requireResidentKey').prop("checked")
        },
        attestation: "none",
        //extensions
    };
    let credentialCreationOptions = {
        publicKey: makePublicKeyCredentialOptions
    };

    navigator.credentials.create(credentialCreationOptions).then(function(credential){
        console.log(credential);
        let clientData = credential.response.clientDataJSON;
        let attestationObject = credential.response.attestationObject;
        // let clientExtensions = credential.getClientExtensionResults(); //Edge preview throws exception as of build 180603-1447
        let clientExtensions = {};
        _this.addCredentialForm(userHandle, clientData, attestationObject, clientExtensions);
    }).catch(function(error){
        console.error(error);
    });
};

UserUpdateViewModel.prototype.addCredentialForm = function (clientData, attestationObject, clientExtensions) {
    let _this = this;

    $('<tr />', { class: "authenticator-item" })
        .append($('<td />')
            .append($('<input />', { type: "text", name: "newAuthenticators["+ _this._authenticatorListIndex +"].name", value: "", class: "form-control input", placeholder: "Authenticator Name"}))
            .append($('<input />', { type: "hidden", name: "newAuthenticators["+ _this._authenticatorListIndex +"].clientData", value: base64url.encode(clientData)}))
            .append($('<input />', { type: "hidden", name: "newAuthenticators["+ _this._authenticatorListIndex +"].attestationObject", value: base64url.encode(attestationObject)}))
            .append($('<input />', { type: "hidden", name: "newAuthenticators["+ _this._authenticatorListIndex +"].clientExtensionsJSON", value: JSON.stringify(clientExtensions)}))
            .append($('<input />', { type: "hidden", name: "newAuthenticators["+ _this._authenticatorListIndex +"].delete", value: false, class: "delete"}))
        )
        .append($('<td />')
            .append(
                $('<button type="button" class="btn btn-box-tool remove-button"><i class="fa fa-remove"></i></button>')
                    .on('click', function(e){ $(this).closest('tr.authenticator-item').fadeOut().find('input.delete').val('true');})
            )
        )
    .appendTo($('#authenticator-list'));

    _this._authenticatorListIndex++;
};

UserUpdateViewModel.prototype.setupEventListeners = function () {
    let _this = this;
    $('#add-credential-button').on('click', function(e){
        _this.addCredential();
    });
    $('#authenticator-list .remove-button').on('click', function(){
        $(this).closest('tr.authenticator-item').fadeOut().find('input.delete').val('true');
    });
};

module.exports = new UserUpdateViewModel();
