async function filter(r) {
    let reply = await r.subrequest('/oauth2/auth')
    let status = reply.status
    let subdomain = r.headersIn.Host.match("(^|^[^:]+:\/\/|[^\.]+)[\w+\.]+")[0].slice(0,-1)
    r.error("+++ DOMAIN +++ "+subdomain)
    r.error("+++ FILTER +++ "+JSON.stringify(reply))
    
    if (reply.status >= 200 && reply.status <= 299) {
        r.error("User: "+reply.headersOut["X-Auth-Request-Preferred-Username"]+" ("+reply.headersOut['X-Auth-Request-Email']+")")    
    try {
        let tenant = jwt(reply.headersOut['X-Auth-Request-Access-Token']).payload.tenant
        r.error("Tenant: "+tenant)
        if (tenant !== subdomain) {
            r.error("+++ Invalid tenant +++ ("+tenant+")")
            status = 403
        }
    } catch (error) {   
        r.error(JSON.stringify(error))
    }
    }
    
    r.headersOut['X-Auth-Request-Access-Token'] = reply.headersOut['X-Auth-Request-Access-Token']
    r.return(status)
}

function jwt(data) {
    var parts = data.split('.').slice(0,2)
        .map(v=>Buffer.from(v, 'base64url').toString())
        .map(JSON.parse);
    return { headers:parts[0], payload: parts[1] };
}

export default { filter }