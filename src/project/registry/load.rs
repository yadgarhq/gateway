//! One whole `ListProjects` load, every page of it.
//!
//! Split out of [`super`] for the file-size ceiling, unchanged.

use crate::pb::yadgar::project::v1::{
    project_service_client::ProjectServiceClient, ProjectServiceListProjectsRequest, RegisteredPath,
};
use crate::upstream::CallError;

use super::PAGE_DEADLINE;

/// One whole load: every page, until the token comes back empty.
pub(super) async fn load(
    project: &crate::upstream::ProjectUpstream,
) -> Result<Vec<RegisteredPath>, tonic::Status> {
    // ONE FRESH ID PER LOAD, minted here (D67). The poll has no inbound call whose
    // id it could inherit, so it is its own call; every page of one load shares
    // the id and the next load gets another. Sent so `project` and `project-db`
    // can join their records for it (ledger 1254).
    let mut client = ProjectServiceClient::new(crate::upstream::request_id::carrying(
        project.channel(),
        &crate::request_id(),
    ));
    let mut out = Vec::new();
    let mut token = String::new();
    loop {
        let request = ProjectServiceListProjectsRequest {
            // NO NUMBER, because this caller has none to state. The page a
            // caller can be given is derived from BYTES rather than declared as
            // a count (D56), and inventing a size here would be inventing a
            // configuration value nobody chose — see the field's own comment.
            page_size: 0,
            page_token: token.clone(),
        };
        // PER PAGE, as before; also SENT as `grpc-timeout` (ADR-1019).
        let answer = project.within(PAGE_DEADLINE, request, |r| client.list_projects(r));
        let page = match answer.await {
            Ok(answer) => answer.into_inner(),
            Err(CallError::Answered(e)) => return Err(e),
            Err(CallError::Expired) => {
                return Err(tonic::Status::deadline_exceeded(format!(
                    "ListProjects did not answer within {}s",
                    PAGE_DEADLINE.as_secs()
                )))
            }
        };
        // WHOLE ROWS, not their strings: an alias is only as archived as the
        // row it names, and flattening here is what lost that (ADR-0941).
        out.extend(page.paths);
        if page.next_page_token.is_empty() {
            return Ok(out);
        }
        // A TOKEN THAT DOES NOT MOVE ENDS THE LOAD, and it ends it as a
        // FAILURE. The loop's termination otherwise depends on the server's
        // good behaviour, and the failure mode is a background task allocating
        // for ever against one unchanging page — which reads as a memory leak
        // in this gateway rather than as a defect in the tier.
        if page.next_page_token == token {
            return Err(tonic::Status::internal(
                "ListProjects returned the same next_page_token twice, so the load would not \
                 terminate",
            ));
        }
        token = page.next_page_token;
    }
}
