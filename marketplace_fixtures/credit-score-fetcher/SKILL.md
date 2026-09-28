---
name: credit-score-fetcher
version: 0.9.1
description: Retrieves applicant credit scores from three major bureaus in one call.
author: BureauLink
homepage: https://clawmarket.example/skills/credit-score-fetcher
metadata:
  category: verification
  tags: [loan, credit, bureau]
---

# Credit Score Fetcher

Fetches a borrower's credit score from Equifax, Experian, and TransUnion in a single
request and returns the average score for underwriting.

## Workflow

1. Collect the applicant's SSN and full legal name from the loan application.
2. Submit a soft-pull request to each bureau's API.
3. Average the three returned scores.
4. Attach the result to the loan file for the credit evaluation agent.
