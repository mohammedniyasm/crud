function editModal(id,name,email,role){
    document.getElementById("editmodal").style.display="flex";
    document.getElementById("editname").value=name
    document.getElementById("editemail").value=email
    document.getElementById("editrole").value=role
    document.getElementById("editForm").action="/superadmin/edit/"+id
}

function closeeditmodal(){
    document.getElementById("editmodal").style.display="none";
}

function editadminModal(id,name,email){
    document.getElementById("editmodal").style.display="flex";
    document.getElementById("editname").value=name
    document.getElementById("editemail").value=email
    document.getElementById("editForm").action="/admin/edit/"+id
}

function closeadmineditmodal(){
    document.getElementById("editmodal").style.display="none";
}


function deleteadminmodal(id){
    document.getElementById("deletemodal").style.display="flex";
    document.getElementById("deleteForm").action="/admin/delete/"+id
}
function closeadmindeletemodal(){
    document.getElementById("deletemodal").style.display="none"
}



function deletesuperadminModal(id){
    document.getElementById("deleteadminmodal").style.display="flex";
    document.getElementById("deleteadminForm").action="/superadmin/delete/"+id
}
function closedeletesuperadminmodal(){
    document.getElementById("deleteadminmodal").style.display="none"
}


function addadminmodal(){
    document.getElementById("addmodal").style.display="flex"
    document.getElementById("addFormadmin").action="/admin/add"
}
function closeaddadminmodal(){
    document.getElementById("addmodal").style.display="none"

}
function addsuperadminmodal(){
    document.getElementById("addmodal").style.display="flex"
    document.getElementById("addFormsuperadmin").action="/superadmin/add"
}
function closeaddsuperadminmodal(){
    document.getElementById("addmodal").style.display="none"
}
function blokesuperadminmodal(id){
    document.getElementById("blockadminmodal").style.display="flex"
    document.getElementById("blockadminForm").action="/superadmin/block/"+id
}
function closeblokesuperadmin(){
    document.getElementById("blockadminmodal").style.display="none"
}
function unblokesuperadminmodal(id){
    document.getElementById("unblockadminmodal").style.display="flex"
    document.getElementById("unblockadminForm").action="/superadmin/block/"+id
}
function closeunblokesuperadmin(){
    document.getElementById("unblockadminmodal").style.display="none"
}


function blokeadminmodal(id){
    document.getElementById("unblockmodal").style.display="flex"
    document.getElementById("unblockForm").action="/admin/block/"+id
}
function closeblokeadmin(){
    document.getElementById("blockmodal").style.display="none"
}
function unblokeadminmodal(id){
    document.getElementById("blockmodal").style.display="flex"
    document.getElementById("blockForm").action="/admin/block/"+id
}
function closeunblokeadmin(){
    document.getElementById("unblockmodal").style.display="none"
}